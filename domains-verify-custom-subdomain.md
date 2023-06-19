# Overview 
[click on this link](#Step1)


# Step 1

## Change subdomain authentication type in Azure Active Directory
#
After a root domain is added to Azure Active Directory (Azure AD), part of Microsoft Entra, all subsequent subdomains added to that root in your Azure AD organization automatically inherit the authentication setting from the root domain. However, if you want to manage domain authentication settings independently from the root domain settings, you can now with the Microsoft Graph API. For example, if you have a federated root domain such as contoso.com, this article can help you verify a subdomain such as child.contoso.com as managed instead of federated.

In the Azure portal, when the parent domain is federated and the admin tries to verify a managed subdomain on the **Custom domain names** page, you'll get a 'Failed to add domain' error with the reason "One or more properties contains invalid values." If you try to add this subdomain from the Microsoft 365 admin center, you will receive a similar error. For more information about the error, see [A child domain doesn't inherit parent domain changes in Office 365, Azure, or Intune](/office365/troubleshoot/administration/child-domain-fails-inherit-parent-domain-changes).

Because subdomains inherit the authentication type of the root domain by default, you must promote the subdomain to a root domain in Azure AD using the Microsoft Graph so you can set the authentication type to your desired type.

## Add the subdomain

1. Use PowerShell to add the new subdomain, which has its root domain's default authentication type. The Azure AD and Microsoft 365 admin centers don't yet support this operation.

   ```powershell
   New-MsolDomain -Name "child.mydomain.com" -Authentication Federated
   ```

1. Use the following example to GET the domain. Because the domain isn't a root domain, it inherits the root domain authentication type. Your command and results might look as follows, using your own tenant ID:

> [!Note]
> Issuing this request can be performed directly in [Graph Explorer](https://aka.ms/ge).

   ```http
   GET https://graph.microsoft.com/v1.0/domains/foo.contoso.com/
   
   Return:
     {
         "authenticationType": "Federated",
         "availabilityStatus": null,
         "isAdminManaged": true,
         "isDefault": false,
         "isDefaultForCloudRedirections": false,
         "isInitial": false,
         "isRoot": false,          <---------------- Not a root domain, so it inherits parent domain's authentication type (federated)
         "isVerified": true,
         "name": "child.mydomain.com",
         "supportedServices": [],
         "forceDeleteState": null,
         "state": null,
         "passwordValidityPeriodInDays": null,
         "passwordNotificationWindowInDays": null
     },
   ```

## Change subdomain to a root domain

Use the following command to promote the subdomain:

```http
POST https://graph.microsoft.com/v1.0/{tenant-id}/domains/foo.contoso.com/promote
```

### Permissions for Graph Explorer 
![Alt text](GraphExplorerPerms.png)

### Example of setting promote on the url inside Graph Explorer
![Alt text](GraphExplorerPromoteDomain.png)

Now that the subdomain/domain is considered "root" we can now run the commands to put the domain in Managed Auth mode. 

### Promote command error conditions

Scenario | Method | Code | Message
-------- | ------ | ---- | -------
Invoking API with a subdomain whose parent domain is unverified | POST | 400 | Unverified domains cannot be promoted. Please verify the domain before promotion.
Invoking API with a federated verified subdomain with user references | POST | 400 | Promoting a subdomain with user references is not allowed. Please migrate the users to the current root domain before promotion of the subdomain.


### Change the subdomain authentication type

1. Use the following command to change the subdomain authentication type:

   ```powershell
   Set-MsolDomainAuthentication -DomainName child.mydomain.com -Authentication Managed
   ```

1. Verify via GET in Microsoft Graph API that subdomain authentication type is now managed:

   ```http
   GET https://graph.microsoft.com/v1.0/domains/foo.contoso.com/
   
   Return:
     {
         "authenticationType": "Managed",   <---------- Now this domain is successfully added as Managed and not inheriting Federated status
         "availabilityStatus": null,
         "isAdminManaged": true,
         "isDefault": false,
         "isDefaultForCloudRedirections": false,
         "isInitial": false,
         "isRoot": true,   <------------------------------ Also a root domain, so not inheriting from parent domain any longer
         "isVerified": true,
         "name": "child.mydomain.com",
         "supportedServices": [
             "Email",
             "OfficeCommunicationsOnline",
             "Intune"
         ],
         "forceDeleteState": null,
         "state": null,
         "passwordValidityPeriodInDays": null,
         "passwordNotificationWindowInDays": null }
   ```
#

# Configure federation between Google Workspace and Azure AD

This article describes the steps required to configure Google Workspace as an identity provider (IdP) for Azure AD.\
Once configured, users will be able to sign in to Azure AD with their Google Workspace credentials.

## Prerequisites

To configure Google Workspace as an IdP for Azure AD, the following prerequisites must be met:

1. An Azure AD tenant, with one or multiple custom DNS domains (that is, domains that aren't in the format \**.onmicrosoft.com*)
    - If the federated domain hasn't yet been added to Azure AD, you must have access to the DNS domain to create a DNS record. This is required to verify the ownership of the DNS namespace
    - Learn how to [Add your custom domain name using the Azure Active Directory portal](/azure/active-directory/fundamentals/add-custom-domain)
1. Access to Azure AD with an account with the *Global Administrator* role
1. Access to Google Workspace with an account with *super admin* privileges

To test federation, the following prerequisites must be met:

1. A Google Workspace environment, with users already created
    > [!IMPORTANT]
    > Users require an email address defined in Google Workspace, which is used to match the users in Azure AD.
    > For more information about identity matching, see [Identity matching in Azure AD](federated-sign-in.md#identity-matching-in-azure-ad).
1. Individual Azure AD accounts already created: each Google Workspace user will require a matching account defined in Azure AD. These accounts are commonly created through automated solutions, for example:
    - School Data Sync (SDS)
    - Azure AD Connect sync for environment with on-premises AD DS
    - PowerShell scripts that call the Microsoft Graph API
    - Provisioning tools offered by the IdP - this capability is offered by Google Workspace through [auto-provisioning](https://support.google.com/a/answer/7365072)

## Configure Google Workspace as an IdP for Azure AD

1. Sign in to the [Google Workspace Admin Console](https://admin.google.com) with an account with *super admin* privileges
1. Select **Apps > Web and mobile apps**
1. Select **Add app > Search for apps** and search for *microsoft*
1. In the search results page, hover over the *Microsoft Office 365 - Web (SAML)* app and select **Select**
   :::image type="content" source="images/google/google-admin-search-app.png" alt-text="Screenshot showing Google Workspace and the search button for Microsoft Office 365 SAML app.":::
1. On the **Google Identity Provider details** page, select **Download Metadata** and take note of the location where the **IdP metadata** - *GoogleIDPMetadata.xml* - file is saved, as it will be used to setup Azure AD later
1. On the **Service provider detail*s** page
      - Select the option **Signed response**
      - Verify that the Name ID format is set to **PERSISTENT**
      - Depending on how the Azure AD users have been provisioned in Azure AD, you may need to adjust the **Name ID** mapping.\
        If using Google auto-provisioning, select **Basic Information > Primary email**
      - Select **Continue**
1. On the **Attribute mapping** page, map the Google attributes to the Azure AD attributes

    |Google Directory attributes|Azure AD attributes|
    |-|-|
    |Basic Information: Primary Email|App attributes: IDPEmail|

    > [!IMPORTANT]
    > You must ensure that your the Azure AD user accounts email match those in your Google Workspace.

1. Select **Finish**

Now that the app is configured, you must enable it for the users in Google Workspace:

1. Sign in to the [Google Workspace Admin Console](https://admin.google.com) with an account with *super admin* privileges
1. Select **Apps > Web and mobile apps**
1. Select **Microsoft Office 365**
1. Select **User access**
1. Select **ON for everyone > Save**

## Configure Azure AD as a Service Provider (SP) for Google Workspace

The configuration of Azure AD consists of changing the authentication method for the custom DNS domains. This configuration can be done using PowerShell.\
Using the **IdP metadata** XML file downloaded from Google Workspace, modify the *$DomainName* variable of the following script to match your environment, and then run it in a PowerShell session. When prompted to authenticate to Azure AD, use the credentials of an account with the *Global Administrator* role.

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Microsoft.Graph

$domainId = "<your domain name>"

$xml = [Xml](Get-Content GoogleIDPMetadata.xml)

$cert = -join $xml.EntityDescriptor.IDPSSODescriptor.KeyDescriptor.KeyInfo.X509Data.X509Certificate.Split()
$issuerUri = $xml.EntityDescriptor.entityID
$signinUri = $xml.EntityDescriptor.IDPSSODescriptor.SingleSignOnService | ? { $_.Binding.Contains('Redirect') } | % { $_.Location }
$signoutUri = "https://accounts.google.com/logout"
$displayName = "Google Workspace Identity"
Connect-MGGraph -Scopes "Domain.ReadWrite.All", "Directory.AccessAsUser.All"

$domainAuthParams = @{
  DomainId = $domainId
  IssuerUri = $issuerUri
  DisplayName = $displayName
  ActiveSignInUri = $signinUri
  PassiveSignInUri = $signinUri
  SignOutUri = $signoutUri
  SigningCertificate = $cert
  PreferredAuthenticationProtocol = "saml"
  federatedIdpMfaBehavior = "acceptIfMfaDoneByFederatedIdp"
}

New-MgDomainFederationConfiguration @domainAuthParams
```

To verify that the configuration is correct, you can use the following PowerShell command:

```powershell
Get-MgDomainFederationConfiguration -DomainId $domainId |fl
```

```output
ActiveSignInUri                       : https://accounts.google.com/o/saml2/idp?idpid=<GUID>
DisplayName                           : Google Workspace Identity
FederatedIdpMfaBehavior               : acceptIfMfaDoneByFederatedIdp
Id                                    : 3f600dce-ab37-4798-9341-ffd34b147f70
IsSignedAuthenticationRequestRequired :
IssuerUri                             : https://accounts.google.com/o/saml2?idpid=<GUID>
MetadataExchangeUri                   :
NextSigningCertificate                :
PassiveSignInUri                      : https://accounts.google.com/o/saml2/idp?idpid=<GUID>
PreferredAuthenticationProtocol       : saml
PromptLoginBehavior                   :
SignOutUri                            : https://accounts.google.com/logout
SigningCertificate                    : <BASE64 encoded certificate>
AdditionalProperties                  : {}
```

## Verify federated authentication between Google Workspace and Azure AD

From a private browser session, navigate to https://portal.azure.com and sign in with a Google Workspace account:

1. As username, use the email as defined in Google Workspace
1. The user will be redirected to Google Workspace to sign in
1. After Google Workspace authentication, the user will be redirected back to Azure AD and signed in

:::image type="content" source="images/google/google-sso.gif" alt-text="A GIF that shows the user authenticating the Azure portal using a Google Workspace federated identity.":::
