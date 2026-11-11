<#--
    Shared building blocks for the OpenID4VP login page (login-oid4vp-v2.ftl).
    So customizations may reuse the blocks easily.
-->

<#--
    Header and form content for the presentation-during-issuance step.
    By default presentation is triggered automatically, so this step only reports errors.
    @param section the section requested by the layout (e.g. "header", "form")
-->
<#macro presentationDuringIssuance section>
    <#if section = "header">
        ${msg('oid4vpPresentationDuringIssuanceTitle')}
    <#elseif section = "form">
        <#if oid4vp.authContext.error>
            <p class="pf-v5-u-mb-md">
                ${msg('oid4vpPresentationDuringIssuanceError')}
            </p>
        </#if>
    </#if>
</#macro>

<#--
    Completion form and status polling for the presentation page (scan QR code).
-->
<#macro completionForm>
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
</#macro>
