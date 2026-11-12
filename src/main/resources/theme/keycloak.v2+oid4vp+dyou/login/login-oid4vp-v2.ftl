<#import "template.ftl" as layout>
<#import "login-oid4vp-v2-macros.ftl" as oid4vpLayout>

<#-- OID4VP has no username step; prevent keycloak.v2 from rendering its attempted-username block. -->
<#global auth = {}>

<@layout.registrationLayout displayMessage=false displayInfo=false; section>
    <!-- template: login-oid4vp-v2.ftl (keycloak.v2+oid4vp+dyou) -->

    <#if oid4vp.isPresentationDuringIssuance()>
        <@oid4vpLayout.presentationDuringIssuance section=section />
    <#else>
        <#if section = "form">
            <div class="dyou-card pf-v5-u-p-lg pf-v5-u-text-align-center">
                <h1 class="dyou-title pf-v5-u-mt-0 pf-v5-u-mb-md
                           pf-v5-u-font-size-4xl pf-v5-u-font-weight-bold">
                    ${msg('dyouTitle')}
                </h1>
                <p class="dyou-text pf-v5-u-mt-0 pf-v5-u-mb-md
                          pf-v5-u-font-size-md">
                    ${msg('dyouOtherDevicePrompt')}
                </p>

                <div class="kc-qr-code">
                    <img src="${oid4vp.authContext.authReqQrCode}"
                         id="kc-oid4vp-qrcode"
                         alt="QR Code" />
                </div>

                <p class="dyou-divider pf-v5-u-mt-lg pf-v5-u-mb-lg pf-v5-u-font-size-md">
                    ${msg('dyouWalletDividerLbl')}
                </p>

                <p class="dyou-text pf-v5-u-mt-0 pf-v5-u-mb-md pf-v5-u-font-size-md">
                    ${msg('dyouSameDevicePrompt')}
                </p>

                <a href="${oid4vp.authContext.authReqLink}"
                   id="kc-oid4vp-link" class="kc-dyou-wallet-button pf-v5-u-mt-0 pf-v5-u-mb-lg">
                    <img src="${url.resourcesPath}/img/${msg('dyouWalletButtonAsset')}"
                         alt="${msg('dyouWalletButtonLbl')}" />
                </a>

                <a href="https://eudi-wallet.gov.de"
                   class="dyou-info-link pf-v5-u-mt-0 pf-v5-u-mb-md pf-v5-u-font-size-md"
                   target="_blank"
                   rel="noopener noreferrer">
                    ${msg('dyouWalletInfoLinkLbl')}
                </a>
            </div>

            <@oid4vpLayout.completionForm />
        </#if>
    </#if>

</@layout.registrationLayout>
