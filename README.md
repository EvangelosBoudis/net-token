```console
NetToken % dotnet ef migrations add Init --project Infrastructure --startup-project Api -o Store/Migrations
NetToken % dotnet ef database update --project Infrastructure --startup-project Api
```