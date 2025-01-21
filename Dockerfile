FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy csproj files and restore dependencies
COPY ["src/AuthService.API/AuthService.API.csproj", "src/AuthService.API/"]
COPY ["src/AuthService.Application/AuthService.Application.csproj", "src/AuthService.Application/"]
COPY ["src/AuthService.Domain/AuthService.Domain.csproj", "src/AuthService.Domain/"]
COPY ["src/AuthService.Infrastructure/AuthService.Infrastructure.csproj", "src/AuthService.Infrastructure/"]
RUN dotnet restore "src/AuthService.API/AuthService.API.csproj"

# Copy the rest of the code
COPY . .
WORKDIR "/src/src/AuthService.API"

# Build and publish
RUN dotnet build "AuthService.API.csproj" -c Release -o /app/build
RUN dotnet publish "AuthService.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app

# Create non-root user
RUN addgroup --system --gid 1000 appgroup && \
    adduser --system --uid 1000 --ingroup appgroup --shell /bin/sh appuser

# Copy the published app and set permissions
COPY --from=build /app/publish .
RUN chown -R appuser:appgroup /app

USER appuser
EXPOSE 80
EXPOSE 443
ENTRYPOINT ["dotnet", "AuthService.API.dll"]