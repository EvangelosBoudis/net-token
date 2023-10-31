```console
dotnet ef migrations add Init --project Infrastructure --startup-project Api -o Store/Migrations
dotnet ef database update --project Infrastructure --startup-project Api

docker build --no-cache -t net-api .
docker run -p 8080:80 net-api
```