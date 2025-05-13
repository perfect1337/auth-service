# Установка swag, если не установлен
if (-not (Get-Command swag -ErrorAction SilentlyContinue)) {
    Write-Host "Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
}

# Переход в корневую директорию проекта
Set-Location $PSScriptRoot/..

# Генерация документации
Write-Host "Generating Swagger documentation..."
swag init -g cmd/main.go --parseDependency --parseInternal

Write-Host "Swagger documentation generated successfully!" 