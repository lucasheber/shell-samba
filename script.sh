#!/bin/bash

# Constantes
NT_STATUS_LOGON_FAILURE="NT_STATUS_LOGON_FAILURE"
NT_STATUS_CONNECTION_REFUSED="NT_STATUS_CONNECTION_REFUSED"
UNIDADE_HOME="H"
UNIDADE_ARQUIVOS="X"
DIR_ARQUIVOS="/home/samba/arquivos"

# Configuraçoes
workgroup=$1 # Nome do dominio via parametro
arquivoTeste="testparm.txt"
usersmb=$2
passuser=$3

# Servidor Proxy
pass="One8399*"
proxyServer="192.168.1.130"
proxyUser="root"

# Servidor Samba
passSamba="One8399*"
sambaServer="192.168.10.10"
sambaUser="root"

verificando_servicos()
{
    # Configurações do samba
    smbclient="smbclient -W $workgroup -L 127.0.0.1 -U $usersmb%$passuser"
    smbactive="systemctl is-active smb nmb" # Verificando se os servicos Samba estao ativos
    smbenable="systemctl is-enabled smb nmb" # Verificando se os servicos Samba estao ativos

    smbclientSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbclient""
    smbcliuser=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$smbclientSSH | grep $usersmb"`

    smbclientSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbclient""
    smbcliuser=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$smbclientSSH | grep $usersmb"`

    smbclientSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbclient""
    smbcliuser=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$smbclientSSH | grep $usersmb"`

}
# ################################################################################### # 
#                          PEGANDO OS DADOS NECESSARIOS                               #
# ################################################################################### #

# Configurações do samba
smbclient="smbclient -W $workgroup -L 127.0.0.1 -U $usersmb%$passuser"
testparm="testparm -s"
smbactive="systemctl is-active smb nmb" # Verificando se os servicos Samba estao ativos
smbenable="systemctl is-enabled smb nmb" # Verificando se os servicos Samba estao ativos

# Verificando o smbclient
smbclientSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbclient""
##smbcliuser=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$smbclientSSH | grep $usersmb"`

# Acessando o samba e executando o $testparm
##sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$testparm""

# Acessando o proxy e obtendo o resultado do $testparm do servidor samba
## sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH" > $arquivoTeste 2> /dev/null

# Verificando se o smb e nmb estao ativos
sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbactive""
##smbactstatus=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH"`

# Verificando se o smb e nmb estao "enabled"
sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbenable""
##smbenastatus=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH"`

# Pegando somente a primeira linha
# echo "$smbenastatus" | sed -n '1p'

users="cat /etc/passwd | egrep 'pedrito|palito|palhaco'"
##userslinux=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$users"`
##echo $userslinux

# ################################################################################### # 
#                          PEGANDO OS VALORES DO TESTPARM                             #
# ################################################################################### #

## Pegando o os valores necessarios para PDC
preferred=`cat $arquivoTeste | grep 'preferred master =' | awk '{ print $NF}'`
domain=`cat $arquivoTeste | grep 'domain master =' | awk '{ print $NF}'`
logons=`cat $arquivoTeste | grep 'domain logons =' | awk '{ print $NF}'`
invaliduser=`cat $arquivoTeste | grep 'invalid users = root' | awk '{ print $NF}'`
workgroup=`cat $arquivoTeste | grep 'workgroup =' | awk '{ print $NF}'`
bindinterface=`cat $arquivoTeste | grep 'bind interfaces only =' | awk '{ print $NF }'`
interfaces=`cat $arquivoTeste | grep 'interfaces =' | awk '{ print $(NF-1) " " $NF }'`
security=`cat $arquivoTeste | grep 'security =' | awk '{ print $NF }'`
wins=`cat $arquivoTeste | grep 'wins support =' | awk '{ print $NF }'`

logondrive=`cat $arquivoTeste | grep 'logon drive =' | awk '{ print $NF }'`
logonpath=`cat $arquivoTeste | grep 'logon path =' | awk '{ print $NF }'`
logonscript=`cat $arquivoTeste | grep 'logon script =' | awk '{ print $NF }'`
oslevel=`cat $arquivoTeste | grep 'os level =' | awk '{ print $NF }'`
pathnetlogon=`cat $arquivoTeste | grep -A5 "\[netlogon\]" | grep -m1 "path" | awk '{ print $NF }'`
crlf=`file $pathnetlogon/$logonscript | awk -F: '{ print $2}'`
homes=`cat $arquivoTeste | grep -A6  "\[homes\]" | grep -m1 "read only" | awk '{ print $NF }'`
#echo "cat $arquivoTeste | grep -A6  "\[homes\]" | grep -m1 "read only" | awk '{ print $NF }'"