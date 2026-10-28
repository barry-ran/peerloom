-- 仅回滚此项目的业务表；不删除共享扩展或迁移账本。
DROP TABLE audit_events, webhook_endpoints, relay_nodes, sessions, connection_grants, registration_grants, device_credentials, devices, applications, tenants;
