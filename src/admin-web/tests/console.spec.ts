import {test,expect,type Page} from '@playwright/test';
const tenant=process.env.PEERLOOM_ADMIN_TEST_TENANT!;
const password='Synthetic browser fixture password 123!';
test.beforeAll(()=>{ expect(tenant).toMatch(/^[0-9a-f-]{36}$/); expect(process.env.PEERLOOM_ADMIN_TEST_URL).toMatch(/^http:\/\/(127\.0\.0\.1|\[::1\]):[0-9]+$/); });
async function login(page:Page,user='owner') {
 await page.goto('/admin/');
 await page.getByLabel('租户 ID').fill(tenant); await page.getByLabel('用户名',{exact:true}).fill(user); await page.getByLabel('密码',{exact:true}).fill(password);
 await page.getByRole('button',{name:'安全登录',exact:true}).click(); await expect(page.getByRole('heading',{name:'应用',exact:true})).toBeVisible();
}
test('real login, CSRF, application grant, audit and logout',async({page,context})=>{
 await login(page);
 const cookies=await context.cookies(); const cookie=cookies.find(c=>c.name==='peerloom_admin_dev'); expect(cookie?.httpOnly).toBe(true); expect(cookie?.sameSite).toBe('Strict');
 expect(await page.evaluate(()=>document.cookie)).not.toContain('peerloom_admin_dev');
 const rejected=await page.evaluate(async()=>{const r=await fetch('/admin/api/v1/applications',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'forbidden'})});return r.status;}); expect(rejected).toBe(403);
 await page.getByRole('button',{name:'创建应用',exact:true}).click(); await page.getByLabel('名称',{exact:true}).fill('<img src=x onerror=alert(1)>');
 await page.getByRole('button',{name:'确认',exact:true}).click(); await page.getByRole('button',{name:'确认',exact:true}).click();
 await expect(page.getByRole('cell',{name:'<img src=x onerror=alert(1)>',exact:true})).toBeVisible(); expect(await page.locator('#table-area img').count()).toBe(0);
 await page.getByRole('button',{name:'注册 grant',exact:true}).click(); await page.getByRole('button',{name:'确认',exact:true}).click();
 await expect(page.getByLabel('一次性注册凭证',{exact:true})).toHaveValue(/^reg_/); await page.getByRole('button',{name:'关闭',exact:true}).click(); await expect(page.getByLabel('一次性注册凭证',{exact:true})).toHaveCount(0);
 expect(await page.evaluate(()=>Object.keys(localStorage))).toEqual([]); expect(await page.evaluate(()=>Object.keys(sessionStorage))).toEqual([]);
 await page.getByRole('button',{name:'审计',exact:true}).click(); await expect(page.getByRole('cell',{name:'application.create',exact:true})).toBeVisible();
 await page.getByRole('button',{name:'English',exact:true}).click(); await expect(page.getByRole('heading',{name:'Audit',exact:true})).toBeVisible();
 await page.screenshot({path:'test-results/console-desktop.png',fullPage:true});
 await page.getByRole('button',{name:'Sign out',exact:true}).click(); await expect(page.getByRole('heading',{name:'Sign in to the console',exact:true})).toBeVisible();
 const session=await page.request.get('/admin/api/auth/session'); expect(session.status()).toBe(401);
});
test('read role and responsive layout, invalid password stays visible',async({page})=>{
 await page.setViewportSize({width:390,height:844}); await page.goto('/admin/');
 await page.getByLabel('租户 ID').fill(tenant); await page.getByLabel('用户名',{exact:true}).fill('reader'); await page.getByLabel('密码',{exact:true}).fill('Wrong fixture password');
 await page.getByRole('button',{name:'安全登录',exact:true}).click(); await expect(page.getByRole('alert')).toBeVisible();
 await page.getByLabel('密码',{exact:true}).fill(password); await page.getByRole('button',{name:'安全登录',exact:true}).click();
 await expect(page.getByText('当前账户只能查询，变更由服务端拒绝。')).toBeVisible(); await expect(page.getByRole('button',{name:'创建应用',exact:true})).toHaveCount(0);
 const rejected = await page.evaluate(async()=>{
  const session = await (await fetch('/admin/api/auth/session')).json();
  const result = await fetch('/admin/api/v1/applications',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf_token,'Idempotency-Key':'reader-mutation-must-fail'},body:JSON.stringify({name:'reader forbidden'})});
  return result.status;
 }); expect(rejected).toBe(403);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
 await page.screenshot({path:'test-results/console-mobile.png',fullPage:true});
});

test('committed mutation with lost response retries the same key without duplicate creation',async({page})=>{
 await login(page);
 const keys:string[]=[];
 await page.route(/\/admin\/api\/v1\/applications(?:\?.*)?$/,async route=>{
  if(route.request().method()!=='POST'){await route.continue();return;}
  keys.push(route.request().headers()['idempotency-key']??'');
  if(keys.length===1){
   const committed=await route.fetch(); expect(committed.status()).toBe(201);
   await route.fulfill({status:503,headers:{'Cache-Control':'no-store'},json:{code:'SYNTHETIC_RESPONSE_LOSS'}});
   await committed.dispose();
  }else{await route.continue();}
 });
 await page.getByRole('button',{name:'创建应用',exact:true}).click();
 await page.getByLabel('名称',{exact:true}).fill('browser retry fixture');
 await page.getByRole('button',{name:'确认',exact:true}).click();
 await page.getByRole('button',{name:'确认',exact:true}).click();
 await expect(page.getByRole('alert')).toContainText('SYNTHETIC_RESPONSE_LOSS');
 await expect(page.getByText('结果尚未确认。请保留本页并重试相同请求，不要重复创建。')).toBeVisible();
 await page.screenshot({path:'test-results/console-retry.png',fullPage:true});
 await page.getByRole('button',{name:'使用相同请求重试',exact:true}).click();
 await expect(page.getByRole('cell',{name:'browser retry fixture',exact:true})).toHaveCount(1);
 expect(keys).toHaveLength(2); expect(keys[0]).toMatch(/^[0-9a-f-]{36}$/); expect(keys[1]).toBe(keys[0]);
 expect(await page.evaluate(()=>Object.keys(sessionStorage))).toEqual([]);
 await page.getByRole('button',{name:'退出登录',exact:true}).click();
 await expect(page.getByRole('heading',{name:'登录管理控制台',exact:true})).toBeVisible();
});

test('grant committed before logout never appears on the returned login page',async({page})=>{
 await login(page);
 const current = await page.request.get('/admin/api/auth/session'); expect(current.status()).toBe(200);
 const session = await current.json();
 let committedGrant=false,loggedOut=false,listRejected=false;
 page.on('response',response=>{if(response.url().includes('/admin/api/v1/applications?') && response.status()===401) listRejected=true;});
 await page.route('**/admin/api/v1/registration-grants',async route=>{
  const committed=await route.fetch(); expect(committed.status()).toBe(201); committedGrant=true;
  // Commit the grant, then revoke the REAL session before delivering its delayed response.
  const logout=await page.request.post('/admin/api/auth/logout',{headers:{Origin:process.env.PEERLOOM_ADMIN_TEST_URL!,'X-CSRF-Token':session.csrf_token},data:{}});
  expect(logout.status()).toBe(200); loggedOut=true;
  await route.fulfill({response:committed}); await committed.dispose();
 });
 await page.getByRole('button',{name:'注册 grant',exact:true}).first().click();
 await page.getByRole('button',{name:'确认',exact:true}).click();
 await expect(page.getByRole('heading',{name:'登录管理控制台',exact:true})).toBeVisible();
 await expect.poll(()=>listRejected).toBe(true);
 expect(committedGrant && loggedOut).toBe(true);
 await expect(page.getByLabel('一次性注册凭证',{exact:true})).toHaveCount(0);
 await expect(page.getByRole('dialog')).toHaveCount(0);
 expect(await page.evaluate(()=>Object.keys(localStorage))).toEqual([]);
 expect(await page.evaluate(()=>Object.keys(sessionStorage))).toEqual([]);
 const gone=await page.request.get('/admin/api/auth/session'); expect(gone.status()).toBe(401);
 await page.screenshot({path:'test-results/console-expired-session.png',fullPage:true});
});
