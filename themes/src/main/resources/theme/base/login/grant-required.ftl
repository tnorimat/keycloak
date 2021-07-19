<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("grantRequiredTitle")}
    <#elseif section = "form">
        <div id="kc-terms-text">
            <ul>
                <#if authorizationDetails?has_content>
                    <li>
                        authorization Details: <span>${authorizationDetails}</span>
                    </li>
                </#if>
            </ul>
        </div>
        <form class="form-actions" action="${url.loginAction}" method="POST">
            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="accept" id="kc-accept" type="submit" value="${msg("doYes")}"/>
            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-decline" type="submit" value="${msg("doNo")}"/>
        </form>
        <div class="clearfix"></div>
    </#if>
</@layout.registrationLayout>
