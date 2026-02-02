# Demo de uso de `auth-core` como framework

Esta carpeta muestra cómo usar `auth-core` como una librería dentro de una aplicación.

Para correr el demo:

```powershell
cd demo
go run ./
```

El demo arranca un servidor en `:4000` con los endpoints montados por `auth-core` en `/api/auth` y una ruta protegida `/demo/admin`.

Nota: el demo usa `replace` en `go.mod` para apuntar al módulo local `../`.

