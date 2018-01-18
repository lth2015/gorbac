# 使用casbin构建RBAC认证Demo
============================

### Build
----------
```bash
go build main.go
./main
curl -XPOST http://localhost:8080/auth -d "{\"name\":\"guest\", \"organization\":\"org\", \"method\":\"GET\", \"path\":\"/swagger/\"}"
```
