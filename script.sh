#!/bin/bash

# Constantes
NT_STATUS_LOGON_FAILURE="NT_STATUS_LOGON_FAILURE"
NT_STATUS_CONNECTION_REFUSED="NT_STATUS_CONNECTION_REFUSED"
UNIDADE_HOME="H"
UNIDADE_ARQUIVOS="X"
DIR_ARQUIVOS="/home/samba/arquivos"
PLACA_INTERNA="enp0s8"

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
eval ipinterno=""


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

    sship="ip addr | grep $PLACA_INTERNA | grep inet | awk '{ print \$2 }' | cut -d'/' -f1"
    sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$sship""
    ip=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH"`

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} IP da rede interna: $ip"
        ipinterno="$ip"
    else
        IP=$(whiptail --inputbox "Por favor, foneca seu IP da rede interna" 8 78 --title "IP da rede interna" 3>&1 1>&2 2>&3)
        exitstatus=$?
        if [ $exitstatus = 0 -a ! -z "$IP" ]; then
            echo -e "${GREEN}[SUCCESS]${NC} IP da rede interna: $IP"
            ipinterno="$IP"
        else
            echo -e "${RED}[ERROR]${NC} IP da rede interna nao encontrado!"
            echo "(Exit status was $exitstatus)"
        fi
    fi

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
    homes=$(cat $arquivoTeste | grep -A6 "\[homes\]" | grep -m1 "read only =" | awk '{ print $NF }')

    ## VALIDANDO
    if [ "$preferred" == "Yes" -a "$domain" == "Yes" -a "$logons" == "Yes" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para PDC. (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para PDC. (+0 Pontos)"
    fi

    ## Testar
    if [ "$bindinterface" == "Yes" -a "$interfaces" == "lo $PLACA_INTERNA" -o "$interfaces" == "$PLACA_INTERNA lo" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para somente a rede local ter acesso. (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para somente a rede local ter acesso. (+0 Pontos)"
    fi

    if [ "$logondrive" == "H:" -a "$homes" == "No" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Diretorio home mapeado (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para somente a rede local ter acesso. (+0 Pontos)"
    fi

     #smbclient -U pedrito%123 \\\\INFRA\\arquivos -c 'mkdir teste3'
    # Invalid User
    if [ ! -z $invaliduser ]; then
        echo -e "${YELLOW}[WARNING]${NC} O usuario root esta configuradao para fazer logon!"
    fi

    echo "Total: $pontos pontos";
}

netlogon() {
    pathnetlogon=$1
    tipo=$2 # 1 - diretorio home, 2 - diretorio arquivos

    case $tipo in
        1) 
            neth="cat $pathnetlogon | tr -s ' ' | grep 'net use H: /HOME'"
            sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$neth""
            result=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH"`

            if [ -z "$result" ]; then
                return 1 # ERRO
            else
                return 0 #Ok
            fi
        ;;
        2) 
            neth="cat $pathnetlogon | tr -s ' ' | grep 'net use X: \\\\\\\\$ipinterno\\\arquivos /yes'"
            sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$neth""
            result=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH"`
  
            if [ -z "$result" ]; then
                return 1 # ERRO
            else
                return 0 #Ok
            fi
        ;;
        *) return 1 
        ;;
    esac
}

verificando_servicos
dados_necessarios
#netlogon "/var/lib/samba/netlogon/netlogon.bat" 2
#rm -f $arquivoTeste
