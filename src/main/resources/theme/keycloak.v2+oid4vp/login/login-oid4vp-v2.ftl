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

            <@oid4vpLayout.completionForm />
        </#if>
    </#if>

</@layout.registrationLayout>
