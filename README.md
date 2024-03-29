# Create Windows Users

```
#################
# Set The Brand #
#################
# This will generate users and store passwords temporarily to C:\passwords.txt. DELETE IT !!!!


$brand = "baixo"
$charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789&@#$%'

##########
# GROUPS #
##########

## System ##
New-LocalGroup -Name "$brand.files.webmaster"
New-LocalGroup -Name "$brand.db.admin"

## Database ##
New-LocalGroup -Name "$brand.db.$brand"
New-LocalGroup -Name "$brand.db.mediastore"
New-LocalGroup -Name "$brand.db.uvresources"
New-LocalGroup -Name "$brand.db.forum"
New-LocalGroup -Name "$brand.db.profiles"
New-LocalGroup -Name "$brand.db.crm"
New-LocalGroup -Name "$brand.db.ops"
New-LocalGroup -Name "$brand.db.casino"

## File System ##
New-LocalGroup -Name "$brand.files.prod"
New-LocalGroup -Name "$brand.files.qa"
New-LocalGroup -Name "$brand.files.repo"

#########
# USERS #
#########

#############
# GAME.PROD #
#############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).game.prod = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.game.prod" -Password $securePassword -Description "$brand Production Game"
Set-LocalUser -Name "$brand.game.prod" -PasswordNeverExpires $true
# GROUPS
Add-LocalGroupMember -Group "$brand.db.$brand" -Member "$brand.game.prod"
Add-LocalGroupMember -Group "$brand.db.uvresources" -Member "$brand.game.prod"
Add-LocalGroupMember -Group "$brand.files.prod" -Member "$brand.game.prod"
# DELETE
net localgroup "Users" "$brand.game.prod" /delete

#############
# IIS.ADMIN #
#############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).iis.admin = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.iis.admin" -Password $securePassword -Description "$brand Admin IIS"
Set-LocalUser -Name "$brand.iis.admin" -PasswordNeverExpires $true
# GROUPS
Add-LocalGroupMember -Group "$brand.db.$brand" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.mediastore" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.uvresources" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.forum" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.profiles" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.crm" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.ops" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.db.casino" -Member "$brand.iis.admin"
Add-LocalGroupMember -Group "$brand.files.prod" -Member "$brand.iis.admin"
# DELETE
net localgroup "Users" "$brand.iis.admin" /delete

############
# IIS.GAME #
############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).iis.game = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.iis.game" -Password $securePassword -Description "$brand Game IIS"
Set-LocalUser -Name "$brand.iis.game" -PasswordNeverExpires $true
# GROUPS 
Add-LocalGroupMember -Group "$brand.db.uvresources" -Member "$brand.iis.game"
Add-LocalGroupMember -Group "$brand.files.prod" -Member "$brand.iis.game"
# DELETE
net localgroup "Users" "$brand.iis.game" /delete

##############
# IIS.HYBRID #
##############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).iis.hybrid = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.iis.hybrid" -Password $securePassword -Description "$brand Hybrid IIS"
Set-LocalUser -Name "$brand.iis.hybrid" -PasswordNeverExpires $true
# GROUPS
Add-LocalGroupMember -Group "$brand.db.$brand" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.db.mediastore" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.db.uvresources" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.db.profiles" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.db.crm" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.db.ops" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.db.casino" -Member "$brand.iis.hybrid"
Add-LocalGroupMember -Group "$brand.files.prod" -Member "$brand.iis.hybrid"
# DELETE
net localgroup "Users" "$brand.iis.hybrid" /delete

############
# IIS.MISC #
############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).iis.misc = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.iis.misc" -Password $securePassword -Description "$brand Misc IIS"
Set-LocalUser -Name "$brand.iis.misc" -PasswordNeverExpires $true
# GROUPS 
Add-LocalGroupMember -Group "$brand.db.$brand" -Member "$brand.iis.misc"
Add-LocalGroupMember -Group "$brand.db.mediastore" -Member "$brand.iis.misc"
Add-LocalGroupMember -Group "$brand.files.prod" -Member "$brand.iis.misc"
# DELETE
net localgroup "Users" "$brand.iis.misc" /delete

#############
# IIS.FORUM #
#############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).iis.forum = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.iis.forum" -Password $securePassword -Description "$brand Forum IIS"
Set-LocalUser -Name "$brand.iis.forum" -PasswordNeverExpires $true
# GROUPS 
Add-LocalGroupMember -Group "$brand.db.$brand" -Member "$brand.iis.forum"
Add-LocalGroupMember -Group "$brand.db.forum" -Member "$brand.iis.forum"
Add-LocalGroupMember -Group "$brand.files.prod" -Member "$brand.iis.forum"
# DELETE
net localgroup "Users" "$brand.iis.forum" /delete
```
# Additional Ones
```
##############
# IIS STATIC #
##############
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).iis.static = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.iis.static" -Password $securePassword -Description "$brand Static IIS"
Set-LocalUser -Name "$brand.iis.static" -PasswordNeverExpires $true
# GROUPS 
# DELETE
net localgroup "Users" "$brand.iis.static" /delete

###########
# Billing #
###########
$password = -join (1..32 | ForEach-Object { $charSet.ToCharArray() | Get-Random })
"$($brand).billing.service = $($password)" | Out-File -FilePath "C:\passwords.txt" -Append
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name "$brand.billing.service" -Password $securePassword -Description "$brand Billing.service"
Set-LocalUser -Name "$brand.billing.service" -PasswordNeverExpires $true
# GROUPS 
# DELETE
net localgroup "Users" "$brand.billing.service" /delete

################
# Watermarking #
################
```
