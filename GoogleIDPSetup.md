#STEP 1

Setup a subdomain

#STEP 2

# Run graph explorer 
# Make sure you set the right permissions 
# Domain.ReadWrite.All
# See image below for example 
# https://github.com/adamgell/GoogleIDPNotes/blob/cd247b6a585267f98afd39e2bea06768f528ba6b/GraphExplorerPerms.png
#
#
#

# POST https://graph.microsoft.com/v1.0/e34622a2-5db5-4e6e-86f7-92800755d7e9/domains/hello.gell.one/promote

#STEP 1 

Import-Module Microsoft.Graph

$domainId = "hello.gell.one"

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

#STEP 3
# Set-MsolDomainAuthentication -DomainName hello.gell.one -Authentication Federated






<#
Connect-MgGraph -Scopes Directory.ReadWrite.All
$users = Get-MgUser | Select ID, UserPrincipalName
foreach($user in $users){Update-MgUser -UserId $user.ID -OnPremisesImmutableId $user.UserPrincipalName -Whatif}

OR

$id = ""
$immutableID = "" # calico primary email 

Connect-MgGraph -Scopes Directory.ReadWrite.All
Update-MgUser -UserId $id -OnPremisesImmutableId $immutableID -Whatif


ReneMagi@hello.gell.one
t w"s]"B}2M5qeb8@*n;

GET https://graph.microsoft.com/v1.0/domains/hello.gell.one/
 #>