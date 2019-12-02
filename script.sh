#!/bin/bash

# Constantes
NT_STATUS_LOGON_FAILURE="NT_STATUS_LOGON_FAILURE"
NT_STATUS_CONNECTION_REFUSED="NT_STATUS_CONNECTION_REFUSED"
UNIDADE_HOME="H"
UNIDADE_ARQUIVOS="X"
DIR_ARQUIVOS="/home/samba/arquivos"

# Configuracoes
workgroup=$1 # Nome do dominio via parametro
arquivoTeste="testparm.txt"
usersmb=$2
passuser=$3

# Servidor Proxy
pass="One8399*"
proxyServer="192.168.11.11"
proxyUser="root"

# Servidor Samba
passSamba="One8399*"
sambaServer="192.168.10.10"
sambaUser="root"

RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BGBLUE='\033[44m'
NC='\033[0m' # No Color

eval userslinux=""

# ################################################################################### #
#                             VERIFICANDO OS SERVICOS                                 #
# ################################################################################### #

verificando_servicos() {

    echo -e "\n                    ${BGBLUE} VERIFICANDO OS SERVICOS ${NC}\n"

    # Configuracões do samba
    smbclient="smbclient -W $workgroup -L 127.0.0.1 -U $usersmb%$passuser 2> /dev/null"
    smbactive="systemctl is-active smb nmb"  # Verificando se os servicos Samba estao ativos
    smbenable="systemctl is-enabled smb nmb" # Verificando se os servicos Samba estao ativos

    smbclientSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbclient""
    smbcliuser=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$smbclientSSH | grep $usersmb" 2>/dev/null)

    # Verificando se o smb e nmb estao ativos
    sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbactive""
    smbactstatus=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH")

    # Verificando se o smb e nmb estao "enabled"
    sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbenable""
    smbenastatus=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH")

    result=$(echo "$smbcliuser" | grep "$NT_STATUS_LOGON_FAILURE|$NT_STATUS_CONNECTION_REFUSED" 2>/dev/null)

    if [ -z "$result" -a "$smbcliuser" != "" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} O usuario $usersmb conectou ao servico smbclient!"
    else
        echo -e "${RED}[ERROR]${NC} O usuario $usersmb nao conectou ao servico smbclient!"
    fi

    result=$(echo "$smbactstatus" | sed -n '1p')
    if [ "$result" == "inactive" ]; then
        echo -e "${YELLOW}[WARNING]${NC} O Servico smb esta inativo!"
    else
        echo -e "${GREEN}[SUCCESS]${NC} O Servico smb esta ativo!"
    fi

    result=$(echo "$smbactstatus" | sed -n '2p')
    if [ "$result" == "inactive" ]; then
        echo -e "${YELLOW}[WARNING]${NC} O Servico nmb esta inativo!"
    else
        echo -e "${GREEN}[SUCCESS]${NC} O Servico nmb esta ativo!"
    fi

    result=$(echo "$smbenastatus" | sed -n '1p')
    if [ "$result" == "disaled" ]; then
        echo -e "${YELLOW}[WARNING]${NC} O Servico smb nao esta ativado para iniciar automaticamente!"
    else
        echo -e "${GREEN}[SUCCESS]${NC} O Servico smb esta ativado para iniciar automaticamente!"
    fi

    result=$(echo "$smbenastatus" | sed -n '2p')
    if [ "$result" == "disaled" ]; then
        echo -e "${YELLOW}[WARNING]${NC} O Servico nmb nao esta ativado para iniciar automaticamente!"
    else
        echo -e "${GREEN}[SUCCESS]${NC} O Servico nmb esta ativado para iniciar automaticamente!"
    fi
}

# ################################################################################### #
#                          PEGANDO OS DADOS NECESSARIOS                               #
# ################################################################################### #

dados_necessarios() {
    echo -e "\n                    ${BGBLUE} DADOS NECESSARIOS ${NC}\n"

    # Configuracões do samba
    testparm="testparm -s"

    # Acessando o samba e executando o $testparm
    sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$testparm""

    # Acessando o proxy e obtendo o resultado do $testparm do servidor samba
    sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH" >$arquivoTeste 2>/dev/null

    users="cat /etc/passwd | egrep 'pedrito|palito|palhaco'"
    usersSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$users""
    userslinux=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$usersSSH")

    if [ -f $arquivoTeste ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Arquivo $arquivoTeste gerado!"
        valida_dados
    else
        echo -e "${RED}[ERROR]${NC} Arquivo $arquivoTeste nao foi gerado!"
    fi
}

valida_dados() {
    echo -e "\n                    ${BGBLUE} VALIDANDO OS DADOS ${NC}\n"

    pontos=0
    ## Pegando o os valores necessarios para PDC
    preferred=$(cat $arquivoTeste | grep 'preferred master =' | awk '{ print $NF}')
    domain=$(cat $arquivoTeste | grep 'domain master =' | awk '{ print $NF}')
    logons=$(cat $arquivoTeste | grep 'domain logons =' | awk '{ print $NF}')
    invaliduser=$(cat $arquivoTeste | grep 'invalid users = root' | awk '{ print $NF}')
    workgroup=$(cat $arquivoTeste | grep 'workgroup =' | awk '{ print $NF}')
    bindinterface=$(cat $arquivoTeste | grep 'bind interfaces only =' | awk '{ print $NF }')
    interfaces=$(cat $arquivoTeste | grep 'interfaces =' | awk '{ print $(NF-1) " " $NF }')
    security=$(cat $arquivoTeste | grep 'security =' | awk '{ print $NF }')
    wins=$(cat $arquivoTeste | grep 'wins support =' | awk '{ print $NF }')

    logondrive=$(cat $arquivoTeste | grep 'logon drive =' | awk '{ print $NF }')
    logonpath=$(cat $arquivoTeste | grep 'logon path =' | awk '{ print $NF }')
    logonscript=$(cat $arquivoTeste | grep 'logon script =' | awk '{ print $NF }')
    oslevel=$(cat $arquivoTeste | grep 'os level =' | awk '{ print $NF }')
    pathnetlogon=$(cat $arquivoTeste | grep -A5 "\[netlogon\]" | grep -m1 "path" | awk '{ print $NF }')
    crlf=$(file $pathnetlogon/$logonscript | awk -F: '{ print $2}')
    homes=$(cat $arquivoTeste | grep -A6 "\[homes\]" | grep -m1 "read only" | awk '{ print $NF }')

    ## VALIDANDO
    if [ "$preferred" == "Yes" -a "$domain" == "Yes" -a "$logons" == "Yes" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para PDC. (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para PDC. (+0 Pontos)"
    fi

    if [ "$bindinterface" == "Yes" -a "$interfaces" == "lo enp0s8" -o "$interfaces" == "enp0s8 lo"  ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para somente a rede local ter acesso. (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para somente a rede local ter acesso. (+0 Pontos)"
    fi

    # Invalid User
    if [ ! -z $invaliduser ]; then
        echo -e "${YELLOW}[WARNING]${NC} O usuario root esta configuradao para fazer logon!"
    fi

    echo "Total: $pontos pontos";
}

#verificando_servicos
dados_necessarios
#rm -f $arquivoTeste
