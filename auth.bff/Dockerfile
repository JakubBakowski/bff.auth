FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["auth.bff.csproj", "./"]
RUN dotnet restore "auth.bff.csproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "auth.bff.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "auth.bff.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "auth.bff.dll"] 