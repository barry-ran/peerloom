# Windows 安全存储

## 验证状态与边界

本地预检使用 Rust Windows-MSVC std 在 Linux 上做 `cargo check/clippy`，**这不代表 Windows 链接或运行验证**。必须在 Windows 2022 原生 runner 运行下述测试，实际运行结果以对应精确 SHA 的必需 CI 记录为准；全部成功后才能晋升 master。Wine、WSL、Linux 编译不能替代原生验证。

`device-storage-windows` 是小型 Win32 安全边界；crate 默认 deny unsafe，仅 boundary 模块允许逐处 SAFETY 注释的调用。`device-storage::WindowsDpapiStore` 保持 safe Rust，对上实现相同 load/save-CAS/delete-CAS 契约。验证分支使用与最终交付相同的默认 Windows 创建路径；只有该精确 SHA 的全部必需原生 CI 成功后才晋升 master，不设置另一个测试专用路径。FFI 当前 memory/external 模式不等于自动使用平台存储。

## 数据与文件边界

- 使用 `CryptProtectData/CryptUnprotectData` 的 CurrentUser 语义，设置 `CRYPTPROTECT_UI_FORBIDDEN`，prompt/reserved为空，不设置 LOCAL_MACHINE，不更改或回退进程/线程身份。
- 若线程处于 impersonation 状态则拒绝，避免文件 SID 与 DPAPI 身份不一致；不调用 RevertToSelf。
- 域分离、长度编码后的 origin/application SHA-256 作为可公开 scope 标识及 DPAPI optional entropy；加密快照内再绑定 scope。不能将一个作用域的 blob 搬到另一作用域使用。
- 凭证、device ID、expires_at、revision/tombstone 一起进入 DPAPI 密文；磁盘没有明文身份文件。scope 锁文件仅含空/0/1 标记。
- 仅支持绝对本地 NTFS 盘符路径；拒绝 UNC、设备/ADS、`..`、尾随空格/点、所有 reparse/junction 祖先和目标。父目录须存在。
- 创建最终目录及文件时使用当前 process-token 用户 SID 独占、protected DACL；已有对象必须 owner 匹配、只有一个当前 SID full-control ACE、无继承标志，不能静默修补或接管其他用户文件。
- 所有祖先目录 handle 在事务期间不允许 FILE_SHARE_DELETE，并由 RAII 释放，阻止 rename 导致锁命名空间分裂。锁和数据文件拒绝硬链接。
- 同用户恶意进程、管理员/内核攻陷、用户主动删除/修改存储不在隔离保证内。DPAPI 也存在 roaming profile 等官方例外，不宣称绝对硬件绑定。

## 原子性、取消与退出

所有写入者必须使用相同目录。跨进程文件锁等待至多2秒；revision CAS 在锁内完成，删除保存递增 tombstone 防 ABA。密文先写同目录唯一临时文件并 flush，再以 ReplaceFile（首次为无覆盖同卷 move）替换；不忽略 ACL 合并错误，成功后再次 flush。

修改前持久化 pending=1；成功确认后标记0。崩溃或提交状态不确定保留pending，后续操作 fail closed，不能自动清除标记或新建身份。损坏密文、scope不匹配、已提交blob丢失同样报Unavailable。

DPAPI/Win32文件调用在阻塞工作线程，不在网络/UI线程；全进程最多16个已接受操作。取消调用者future不会强杀已接受系统调用，事务保留锁直至完整结束。**DPAPI可能访问系统profile/域服务，内核或硬盘I/O也可能阻塞，无法安全强制终止；不能把Tokio timeout称为硬退出保证。** 宿主关闭时需等待自己接受的存储请求，或明确进程级退出策略；不在库中强杀线程。当前错误仍归入StorageError::Unavailable，不声称已提供自动pending修复或细粒度用户诊断。

## 必需原生测试

```powershell
cargo test -p device-storage-windows -p device-storage --target x86_64-pc-windows-msvc --locked
cargo clippy -p device-storage-windows -p device-storage --all-targets --target x86_64-pc-windows-msvc --locked -- -D warnings
```

覆盖DPAPI往返/错误scope/篡改拒绝、实际protected DACL、非share-delete目录handle生命周期、原子替换、弱化ACL拒绝、真实junction/硬链接拒绝、子进程重启、两个进程竞争同一revision、取消时等待锁、tombstone、缺失blob/pending failclosed及明文扫描。权限弱化只操作本次临时测试目录中的合成数据，不触碰用户实际文件或账户策略。

`device-core/examples/windows_secure_peer.rs`：与Linux示例一样，必须显式配置 PEERLOOM_ORIGIN/APPLICATION_ID/LOCK_DIR，默认仅DPAPI，不含memory/plaintextfallback。支持受控stdin注册、status以及指定peer的单消息回显；尚未通过Windows真实控制面组合测试，不能仅凭编译宣布完整Windows SDK可用。

## 主要依据

- [DPAPI CurrentUser / UI flags](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [DPAPI integrity and LocalFree ownership](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [CreateFile sharing / reparse semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [GetSecurityInfo descriptor ownership](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [ReplaceFile ACL preservation and failure semantics](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)

## Pending 事故的受控恢复/重置

此版本**没有自动恢复或清除 pending 的 API**；看到 `Unavailable` 不能推断写入未生效。原生 crashpoint 回归会在密文成功替换、清除 journal 前直接结束子进程，验证新revision确已落盘但正常load/save仍失败关闭。

操作流程：停止该 scope 的所有写入进程及自动重启；保留私有ACL的密文blob和锁文件用于诊断；通过应用已有授权管理流程确认服务端身份/凭证状态。若要保留身份，只能恢复经确认仍与服务端一致的完整安全备份（包括scope快照与对应干净journal），然后由应用再次验证self；不能仅将 `1` 改成 `0`。没有这样的备份时，不提供猜测性修复。

若选择**明确重置身份**，先由有权限的操作者吊销旧设备凭证/会话并确认失效，再在所有写入者停止后将该scope的blob和lock成对隔离归档，使用新的注册grant和安装身份执行注册。不得把整个共享目录当作单一scope删除；归档文件仍保持原private DACL。注册本身是显式新身份动作，不伪装成原身份恢复。当前SDK没有替操作者执行服务端吊销或上述归档流程的一键命令；没有完成确认时维持停机fail-closed。
