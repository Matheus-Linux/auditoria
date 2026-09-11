#!/usr/bin/env bash


# ----------------------------------------------------- #
# FUNÇÃO: Escanear host do sistema em busca de\         #
# anomalias                                             #
#                                                       #
# AUTOR: Matheus Alexandre                              #
# CONTATO: matheuspro1@hotmail.com                      #
#                                                       #
# UTILIZAÇÃO: ./auditoria.sh                            #
# ----------------------------------------------------- #


USERS=$(grep -E "(bash|sh)$" /etc/passwd)
GROUPS=$(grep -E "(sudo|wheel)" /etc/group)
SSH_KEYS=/tmp/AUDIT/sshkeys.log
PROCCESS=/tmp/AUDIT/all-proccess.log
PROCCESSDIR=/tmp/AUDIT/all-proccess-dir.log
BASH_LOGS=/tmp/AUDIT/bash-rc-logs.log
SYSTEMD=/tmp/AUDIT/systemd-logs.log
LOGS=/tmp/AUDIT/${HOSTNAME}-auditoria.log
MFILE=/tmp/AUDIT/mtime-files.log
SCALATION=/tmp/AUDIT/suid-files.log
DATA=$(date +'%d-%m-%Y')

if [[ ! -d /tmp/AUDIT ]]; then
        mkdir /tmp/AUDIT
fi


function loading() {
        local VET=( '|' '/' '-' '\' )
        local FUNCTION=$1
        local CONT=0

        for ((v=1;v<50;v++)); {
                if [[ $CONT -gt 4 ]]; then
                        CONT=0
                        echo -en "\e[32;1mColetando informações ${1}\e[m \e[31;1m<--\e[m [${VET[$CONT]}]\r"
                        sleep .1
                fi
                echo -en "\e[32;1mColetando informações ${1}\e[m \e[32;1m<--\e[m [${VET[$CONT]}]\r"
                CONT=$((CONT +1))
                sleep .1
        }
}


function formatlog() {
        TITLE=$1
        echo "-----------------------------" >> $LOGS
        echo "        $TITLE               " >> $LOGS
}

#Coleta informações do kernel da máquina
loading "kernel version"
formatlog "KERNEL VERSION"
uname -a >> $LOGS
echo "----------------------" >> $LOGS

#Coleta o tempo de atividade do host
loading "uptime"
formatlog "UPTIME"
uptime >> $LOGS
echo "----------------------" >> $LOGS

#Coleta informação do host em formato UTC
loading "date"
formatlog "UTC"
date -u >> $LOGS
echo "----------------------" >> $LOGS

#Coleta todos usuários do sistema
loading "all users"
formatlog "USERS"

while read user; do
        echo $user >> $LOGS
done <<< $USERS
echo "----------------------" >> $LOGS

#Coleta inforamções do grupo Wheell/sudo
loading "admin group"
formatlog "ADMIN GROUP"
sed "s/,/\n/g" <(echo $GROUPS) >> $LOGS
echo "----------------------" >> $LOGS

#Coleta informação dos ultimos logins
loading "lastlog"
formatlog "LAST LOGIN"
last -a >> $LOGS
echo "----------------------" >> $LOGS

#Coleta informações de chaves SSH autorizadas
loading "ssh keys"
cat /home/*/.ssh/authorized_keys >> $SSH_KEYS

#Coleta todos processos do sistema
loading "all process"
ps -auxef > $PROCCESS
lsof +D /* > $PROCCESSDIR

#Coleta informações de socket de rede
loading "network socket"
formatlog "NETWORK SOCKETS"
netstat -tulpn >> $LOGS
echo "----------------------" >> $LOGS

#Coleta informações da tabela arp
loading "arp table"
formatlog "ARP TABLE"
arp -n >> $LOGS
echo "----------------------" >> $LOGS

#Coleta informações de ip e gateway
loading "ip configuration"
formatlog "IP CONFIGURATION"
ip a >> $LOGS
echo "" >> $LOGS
ip route >> $LOGS
echo "----------------------" >> $LOGS

#Coleta informações de cron do sistema
loading "crontab info"
formatlog "CRONTAB INFORMATION"
crontab -l >> $LOGS
cat /etc/crontab >> $LOGS
ls -l /etc/cron.* >> $LOGS
echo "----------------------" >> $LOGS

#Coleta todos serviços do systemd habilitado
loading "systemd services enabled"
systemctl list-unit-files --state=enabled >> $SYSTEMD

#Filtra bashrc e .profile de todos usuários
while read user; do
        case "${user/:*}" in
                "root" )
                        echo "CONTEÚDO (bashrc|bashprofile|bash_history) ${user/:*}" >> $BASH_LOGS
                        VETDIR=( '.bash_profile' '.profile' '.bash_history' )
                        for dir in ${VETDIR[@]}; {
                                if [[ ! -f /home/${user/:*}/${dir} ]]; then
                                        echo "/home/${user/:*}/${dir} NULl [x]" >> $BASH_LOGS
                                else
                                        echo "CONTEÚDO DE $dir" >> $BASH_LOGS
                                        cat /home/${user/:*}/${dir} >> $BASH_LOGS
                                fi
                        }

                ;;
                *)
                        echo "CONTEÚDO (bashrc|bashprofile|bash_history) ${user/:*}" >> $BASH_LOGS
                        VETDIR=( '.bash_profile' '.profile' '.bash_history' )
                        for dir in ${VETDIR[@]}; {
                                if [[ ! -f /home/${user/:*}/${dir} ]]; then
                                        echo "/home/${user/:*}/${dir} NULl [x]" >> $BASH_LOGS
                                else
                                        echo "CONTEÚDO DE $dir" >> $BASH_LOGS
                                        cat /home/${user/:*}/${dir} >> $BASH_LOGS
                                fi
                        }
                ;;
        esac
done <<< $USERS

#Coleta arquivos alterados recentemente
loading "mtime files"
find / -mtime -2 -type f > $MFILES

#Coleta possíveis escalada de privilégios
loading "scalation privileges"
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null > $SCALATION

clear

echo -e "\e[32;1mCOLETANDO LOGS DO SISTEMA\e[m"
cp -v /var/log/audit/audit.log /tmp/AUDIT/


if [[ -f /var/log/messages  ]]; then
        cp -v /var/log/messages /tmp/AUDIT/
elif [[ -f /var/log/syslog  ]]; then
        cp -v /var/log/messages /tmp/AUDIT/
else
        :
fi

tar -zcvf /tmp/${HOSTNAME}-${DATA}.tgz /tmp/AUDIT/
rm -f /tmp/AUDIT/* && rmdir /tmp/AUDIT

clear

echo -e "CONSULTAR INFORMAÇÕES EM:/tmp/${HOSTNAME}-${DATA}.tgz"
