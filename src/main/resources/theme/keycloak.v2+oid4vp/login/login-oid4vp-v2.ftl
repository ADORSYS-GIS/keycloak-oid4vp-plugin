<#import "template.ftl" as layout>
<#import "login-oid4vp-v2-macros.ftl" as oid4vpLayout>

<#-- OID4VP has no username step; prevent keycloak.v2 from rendering its attempted-username block. -->
<#global auth = {}>

<@layout.registrationLayout displayMessage=false displayInfo=false; section>
    <!-- template: login-oid4vp-v2.ftl -->

    <#if oid4vp.isPresentationDuringIssuance()>
        <@oid4vpLayout.presentationDuringIssuance section=section />
    <#else>
        <#if section = "header">
            ${msg('oid4vpScanPageTitle')}
        <#elseif section = "form">
            <#-- The QR image has no padding of its own, so a white quiet zone should be drawn,
                 especially for dark-mode renderings. -->
            <div class="pf-v5-u-p-lg pf-v5-u-text-align-center">
                <div class="pf-v5-u-display-inline-block" style="background: white; border-radius: 16px;">
                    <img src="${oid4vp.authContext.authReqQrCode}"
                         class="pf-v5-u-display-block pf-v5-u-p-md"
                         style="width: 250px;"
                         id="kc-oid4vp-qrcode"
                         alt="QR Code" />
                </div>
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

            <@oid4vpLayout.completionForm />
        </#if>
    </#if>

</@layout.registrationLayout>
