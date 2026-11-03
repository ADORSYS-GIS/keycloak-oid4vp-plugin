<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <title>Keycloak</title>
        <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />
    </head>
    <body>
        <script>
            location.replace("${oid4vp.authContext.authReqLink?js_string?no_esc}");
        </script>
    </body>
</html>
