<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false displayInfo=false; section>
<!-- template: login-oid4vp-wallet.ftl -->

    <#if section = "header">
        ${msg('oid4vpScanPageTitle')}
    <#elseif section = "form">
        <div class="pf-v5-u-p-md pf-v5-u-text-align-center">
            <img src="${oid4vp.authContext.authReqQrCode}" 
                 style="max-width: 300px;"
                 alt="QR Code" />
        </div>
        
        <form action="${oid4vp.loginActionUrl}"
              id="kc-oid4vp-completion-form"
              method="post"
              style="display:none;">
            <input type="hidden" id="kc-oid4vp-code-input" name="code" value="" />
        </form>

        <script type="module">
            import { checkAuthStatus } from "${url.resourcesPath}/js/oid4vp.js";
            checkAuthStatus("${oid4vp.authContext.authStatusUrl}", 2500);
        </script>
    </#if>

</@layout.registrationLayout>
