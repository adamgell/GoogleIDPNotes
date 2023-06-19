$PasswordProfile = @{
  Password = 'xWwvJ]6NMw+bWH-d'
  }

New-MgUser -DisplayName 'Rene Magi' -PasswordProfile $PasswordProfile -AccountEnabled -MailNickName 'ReneMagi' -UserPrincipalName 'ReneMagi@hello.gell.one' -OnPremisesImmutableId 'ReneMagi@hello.gell.one'
