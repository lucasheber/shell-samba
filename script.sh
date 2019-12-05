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
pass="123456"
proxyServer="192.168.11.9"
proxyUser="root"

# Servidor Samba
passSamba="123456"
sambaServer="192.168.10.10"
sambaUser="root"

RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BGBLUE='\033[44m'
NC='\033[0m' # No Color

eval userslinux=0
eval usersamba=0
eval ipinterno=""
eval userfragil=""

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

    users="cat /etc/passwd | egrep 'pedrito|palito|palhaco' | cut -d: -f1 | wc -l"
    usersSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$users""
    userslinux=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$usersSSH")

    users="pdbedit -L | egrep 'pedrito|palito|palhaco' | cut -d: -f1 | wc -l"
    usersSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$users""
    usersamba=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$usersSSH")

    users="cat /etc/group | grep fragil | awk -F: '{ print \$NF }'"
    usersSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$users""
    userfragil=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$usersSSH")

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

# ################################################################################### #
#                                    VALIDANDO OS DADOS                               #
# ################################################################################### #

valida_dados() {
    echo -e "\n                    ${BGBLUE} VALIDANDO OS DADOS ${NC}\n"

    pontos=0
    ## Pegando o os valores necessarios para PDC
    preferred=$(cat $arquivoTeste | grep 'preferred master =' | awk '{ print $NF}')
    domain=$(cat $arquivoTeste | grep 'domain master =' | awk '{ print $NF}')
    logons=$(cat $arquivoTeste | grep 'domain logons =' | awk '{ print $NF}')
    invaliduser=$(cat $arquivoTeste | grep 'invalid users = root' | awk '{ print $NF}')
    work=$(cat $arquivoTeste | grep 'workgroup =' | awk '{ print $NF}')
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
    perfis=$(cat $arquivoTeste | grep "\[Profiles\]")
    arquivos=$(cat $arquivoTeste | grep "\[arquivos\]")

    # (03 pts) – alterar todas as configurações necessárias do servidor Samba para que ele se comporte como um PDC; 
    if [ "$preferred" == "Yes" -a "$domain" == "Yes" -a "$logons" == "Yes"  -a $oslevel -gt 100 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para PDC. (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para PDC. (+0 Pontos)"
    fi

    # (02 pts) – criar um domínio com o seu NOME; 
    if [ "$work" == "$workgroup" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Dominio correto. (+2 Pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Dominio incorreto. (+0 Pontos)"
    fi

    # (02 pts) – desabilitar o uso de perfis móveis; 
    if [ -z "$perfis" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Perfis moveis desabilitado. (+2 Pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Perfis moveis habilitado. (+0 Pontos)"
    fi

    # (02 pts) – permitir que somente a rede interna possa acessar o servidor Samba; 
    if [ "$bindinterface" == "Yes" -a "$interfaces" == "lo $PLACA_INTERNA" -o "$interfaces" == "$PLACA_INTERNA lo" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para somente a rede local ter acesso. (+2 Pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para somente a rede local ter acesso. (+0 Pontos)"
    fi

    # (02 pts) – tornar o servidor Samba um servidor WINS; 
    if [ "$wins" == "Yes" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configurado para servidor Wins. (+2 Pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Nao configurado para servidor Wins. (+0 Pontos)"
    fi

    # (03 pts) – mapear o diretório pessoal dos usuários para a unidade “H:”; 
    netlogon "$pathnetlogon/$logonscript" 1
    if [ "$logondrive" == "H:" -a $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Diretorio home mapeado (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Diretorio home nao mapeado. (+0 Pontos)"
    fi

    # (02 pts) – permitir acesso remoto e pleno aos respectivos diretórios pessoais; 
    if [ "$homes" == "No" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Diretorio pessoal liberado (+2 Pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Diretorio pessoal nao liberado. (+0 Pontos)"
    fi

    # (03 pts)- cadastrar os usuários “palhaco”, “palito” e “pedrito” no Linux e no Samba. Os usuários “palhaco” e “palito” devem pertencer ao grupo “fragil
    if [ $usersamba -eq 3 -a $userslinux -eq 3 -a "$userfragil" == "palhaco,palito" -o "$userfragil" == "palito,palhaco" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Usuarios cadastros no linux e no samba (+3 Pontos)"
        pontos=`expr $pontos + 3`
    else
        echo -e "${RED}[ERROR]${NC} Usuarios nao cadastros no linux e no samba (+0 Pontos)"
    fi

    # (06 pts) – criar o diretório “/home/samba/arquivos” e permitir que ele seja compartilhado com o nome “arquivos” e mapeado com a letra “X:” (04 pts),
    # com permissões de leitura e escrita para todo o grupo “fragil” e permissão apenas de leitura para os demais usuários (02 pts); 

    test="[ -d /home/samba/arquivos/ ]"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$test""
    smbcliuser=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui")
    isdirectory=$?

    netlogon "$pathnetlogon/$logonscript" 2
    if [ $? -eq 0 -a "$arquivos" == "[arquivos]" -a $isdirectory -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Diretorio arquivos compartilhado (+4 Pontos)"
        pontos=`expr $pontos + 4`
    else
        echo -e "${RED}[ERROR]${NC} Diretorio arquivos $arquivos nao compartilhado. (+0 Pontos)"
    fi

    test="stat -c '%G' /home/samba/arquivos/"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$test""
    fragil=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui")
 
    test="find /home/samba/arquivos -maxdepth 0 -printf '%m'"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$test""
    permissoes=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui")
    others=`expr $permissoes % 10`
    group=`expr $permissoes / 10`
    group=`expr $group % 10`
 
    
    if [ "$fragil" == "fragil" -a $others -eq 4 -a $group -ge 6 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Permissoes [arquivos] OK! (+2 Pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Permissoes [arquivos] $fragil $permissoes (+0 Pontos)"
    fi

    verifica_mount

    #cat /etc/fstab | grep "/mnt" | cut -d"=" -f2 | cut -d"," -f1
    # Invalid User
    if [ ! -z "$invaliduser" ]; then
        echo -e "${YELLOW}[WARNING]${NC} O usuario root esta configuradao para fazer logon!"
    fi

    echo
    echo "Total: $pontos pontos";
}

# ################################################################################### #
#                                   TESTANDO O NETLOGON                               #
# ################################################################################### #

netlogon() {
    path=$1
    tipo=$2 # 1 - diretorio home, 2 - diretorio arquivos

    case $tipo in
        1) 
            neth="cat $path | tr -s ' ' | grep 'net use H: /HOME'"
            sambaSSH="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$neth""
            result=`sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$sambaSSH"`

            if [ -z "$result" ]; then
                return 1 # ERRO
            else
                return 0 #Ok
            fi
        ;;
        2) 
            neth="cat $path | tr -s ' ' | grep 'net use X: \\\\\\\\$ipinterno\\\arquivos /yes'"
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

verifica_mount() {

    umountmnt="umount /mnt/"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$umountmnt""
    status1=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui" 2> /dev/null)

    mountmnt="mount /mnt/"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$mountmnt""
    status2=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui" 2> /dev/null)

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Diretorio home montado! (+4 pontos)"
        pontos=`expr $pontos + 4`
    else
        echo -e "${RED}[ERROR]${NC} Diretorio nao home montado! (+0 Pontos)"
    fi

    smbpasswd="cat /etc/fstab | grep "/mnt" | cut -d"=" -f2 | cut -d"," -f1"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbpasswd""
    smbpasswd=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui" 2> /dev/null)

    if [ ! -z $smbpasswd -a "$status" == "" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Configuracao no fstab OK! (+2 pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Configuracao invalida no fstab (+0 Pontos)"
    fi

    smbfile="[ -f $smbpasswd ]"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$smbfile""
    smbfile=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui")

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Arquivo externo criado! (+2 pontos)"
        pontos=`expr $pontos + 2`
    else
        echo -e "${RED}[ERROR]${NC} Arquivo externo inexistente (+0 Pontos)"
    fi

    test="find $smbpasswd -maxdepth 0 -printf '%m'"
    ssharqui="sshpass -p $passSamba ssh -o StrictHostKeyChecking=no $sambaUser@$sambaServer "$test""
    permissoes=$(sshpass -p $pass ssh -o StrictHostKeyChecking=no $proxyUser@$proxyServer "$ssharqui" 2> /dev/null)
    
    re='^[0-9]+$'
    if [[ $permissoes =~ $re ]]; then
        onwer=`expr $permissoes / 100`
        others=`expr $permissoes % 10`
        group=`expr $permissoes / 10`
        group=`expr $group % 10`

        if [ $onwer -ge 4 -a $group -eq 0 -a $others -eq 0 ]; then
            echo -e "${GREEN}[SUCCESS]${NC} Permissoes do arquivo configurado corretamente (+2 pontos)"
            pontos=`expr $pontos + 2`
        else
            echo -e "${RED}[ERROR]${NC} Permissoes invalidas (+0 Pontos)"
        fi
    else 
        echo -e "${RED}[ERROR]${NC} Permissoes invalidas (+0 Pontos)"
    fi
}

if [ $# -ne 3 ]; then
    printf "\\n\\t${RED}Quantidade de parametros invalidos!${NC} \\n\\n"
    printf "\\t\\t Sintaxe: $0 WORKGROUP <user_samba> <pass_user_samba> \\n\\n"
else 
    verificando_servicos
    dados_necessarios
fi

exit 0

