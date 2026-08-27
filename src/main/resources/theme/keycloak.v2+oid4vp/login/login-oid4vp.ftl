<#import "template.ftl" as layout>

<#-- OID4VP has no username step; prevent keycloak.v2 from rendering its attempted-username block. -->
<#global auth = {}>

<@layout.registrationLayout displayMessage=false displayInfo=false; section>
    <!-- template: login-oid4vp.ftl -->

    <#if oid4vp.isPresentationDuringIssuance()>
        <#if section = "header">
            ${msg('oid4vpPresentationDuringIssuanceTitle')}
        <#elseif section = "form">
            <#if oid4vp.authContext.error>
                <p class="pf-v5-u-mb-md">
                    ${msg('oid4vpPresentationDuringIssuanceError')}
                </p>
            <#else>
                <p class="pf-v5-u-mb-md">
                    ${msg('oid4vpPresentationDuringIssuancePrompt')}
                </p>
                <div class="pf-v5-u-text-align-center">
                    <a href="${oid4vp.authContext.authReqLink}"
                       id="kc-oid4vp-continue"
                       class="pf-v5-c-button pf-m-primary">
                        ${msg('oid4vpContinueBtnMessage')}
                    </a>
                </div>
            </#if>
        </#if>
    <#else>
        <#if section = "header">
            ${msg('oid4vpScanPageTitle')}
        <#elseif section = "form">
            <div class="pf-v5-u-p-md pf-v5-u-text-align-center">
                <img src="${oid4vp.authContext.authReqQrCode}"
                     style="max-width: 300px;"
                     id="kc-oid4vp-qrcode"
                     alt="QR Code" />
            </div>

            <div class="pf-v5-u-text-align-center">
                <p>${msg('oid4vpSameDevicePrompt')}</p>
                <p>
                    <a href="${oid4vp.authContext.authReqLink}"
                       id="kc-oid4vp-link">
                        ${msg('oid4vpSameDeviceLinkLbl')}
                    </a>
                </p>
            </div>

            <form action="${oid4vp.loginActionUrl}"
                  id="kc-oid4vp-completion-form"
                  method="post"
                  style="display:none;">
                <input type="hidden" id="kc-oid4vp-code-input" name="code" value="" />
            </form>

            <script type="module">
                import { checkAuthStatus } from "${url.resourcesPath}/js/oid4vp.js";
                const transactionId = "${oid4vp.authContext.transactionId!""}";
                const codeVerifier = "${oid4vp.authContext.codeVerifier!""}";
                checkAuthStatus(
                    "${oid4vp.authContext.authStatusUrl}",
                    "${oid4vp.authContext.authCodeRedemptionUrl}",
                    transactionId,
                    codeVerifier,
                    2500
                );
            </script>
        </#if>
    </#if>

</@layout.registrationLayout>
