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

                <div id="kc-dyou-default">
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
                       id="kc-oid4vp-link"
                       class="kc-dyou-wallet-button pf-v5-u-mt-0 pf-v5-u-mb-lg"
                       aria-label="${msg('dyouWalletButtonLbl')}">
                        <img src="${url.resourcesPath}/img/${msg('dyouWalletButtonAsset')}"
                             alt=""
                             aria-hidden="true" />
                    </a>

                    <a href="https://eudi-wallet.gov.de"
                       class="dyou-info-link pf-v5-u-mt-0 pf-v5-u-mb-md pf-v5-u-font-size-md"
                       target="_blank"
                       rel="noopener noreferrer">
                        ${msg('dyouWalletInfoLinkLbl')}
                    </a>
                </div>

                <#-- Guide States: heading → text → visual (spinner / check). -->
                <div id="kc-dyou-loading" class="dyou-status" hidden aria-live="polite">
                    <h1 class="dyou-title pf-v5-u-mt-0 pf-v5-u-mb-md
                               pf-v5-u-font-size-4xl pf-v5-u-font-weight-bold">
                        ${msg('dyouLoadingTitle')}
                    </h1>
                    <p class="dyou-text pf-v5-u-mt-0 pf-v5-u-mb-lg pf-v5-u-font-size-md">
                        ${msg('dyouLoadingText')}
                    </p>
                    <div class="dyou-status-visual" aria-hidden="true">
                        <span class="dyou-spinner"></span>
                    </div>
                </div>

                <div id="kc-dyou-success" class="dyou-status" hidden aria-live="polite">
                    <h1 class="dyou-title pf-v5-u-mt-0 pf-v5-u-mb-md
                               pf-v5-u-font-size-4xl pf-v5-u-font-weight-bold">
                        ${msg('dyouSuccessTitle')}
                    </h1>
                    <p class="dyou-text pf-v5-u-mt-0 pf-v5-u-mb-lg pf-v5-u-font-size-md">
                        ${msg('dyouSuccessText')}
                    </p>
                    <div class="dyou-status-visual" aria-hidden="true">
                        <svg viewBox="0 0 96 96" width="96" height="96" focusable="false">
                            <circle cx="48" cy="48" r="48" fill="#1B7F3A"/>
                            <path d="M28 49.5 L42 63.5 L68 33.5"
                                  fill="none"
                                  stroke="#FFFFFF"
                                  stroke-width="7"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"/>
                        </svg>
                    </div>
                </div>
            </div>

            <@oid4vpLayout.completionForm />
        </#if>
    </#if>

</@layout.registrationLayout>
