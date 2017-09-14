#!/bin/bash

#ficheiro para extrair informação
declare ficheiro_pcap="$1"
declare pasta_saida="$2"
declare numero_argumentos="2"
declare -r aplicacoes="capinfos tshark chaosreader tcptrace tcpdump foremost md5sum sha1sum sha256sum sha512sum tree ngrep" 

#declarar estrutura de pastas
declare pasta_ficheiros_extraidos="$pasta_saida/files"
declare ficheiro_hosts_ipv4="$pasta_saida/hosts/hosts_ipv4.txt"
declare ficheiro_hosts_ipv6="$pasta_saida/hosts/hosts_ipv6.txt"
declare pasta_reports="$pasta_saida/reports/html" 
declare ficheiro_html_reports="$pasta_saida/reports/html/index.html"
declare ficheiro_protocolos="$pasta_saida/protocolos/protocolos.txt"
declare ficheiro_equipamentos_rede="$pasta_saida/equipamentos/equipamentos.txt"
declare ficheiro_informacao_captura="$pasta_saida/captura/informacao_captura.txt"
declare ficheiro_sessoes="$pasta_saida/sessoes/sessoes_captura.txt"
declare ficheiro_email="$pasta_saida/email/email.txt"

declare ficheiro_ligacoes_ethernet="$pasta_saida/ligacoes/ethernet.txt";
declare ficheiro_ligacoes_ipv4e6="$pasta_saida/ligacoes/ipv4e6.txt";
declare ficheiro_ligacoes_tcp="$pasta_saida/ligacoes/tcp.txt";
declare ficheiro_ligacoes_udp="$pasta_saida/ligacoes/udp.txt";


declare ficheiro_top_equipamentos="$pasta_saida/equipamentos/TopEquipamentos.txt";
declare ficheiro_top_equipamentos_ipv4e6="$pasta_saida/equipamentos/TopIPV4eIPV6.txt";
declare ficheiro_top_equipamentos_tcp="$pasta_saida/equipamentos/TopTcp.txt";
declare ficheiro_top_equipamentos_udp="$pasta_saida/equipamentos/TopUdp.txt";

declare ficheiro_portos="$pasta_saida/portos/portos.txt";

declare pasta_pesquisa="$pasta_saida/pesquisa"

declare pasta_hashs="$pasta_saida/hashs";
declare todos_html='';

#mensagens
declare aguarde="Aguarde por favor. O seu pedido está a ser processado..."

#apagar pasta principal
if [ -d "$pasta_saida" ]; 
	then		
		echo "A pasta $pasta_saida já existe."
		echo -e "\n"
		echo "1 - Remover e Continuar "
		echo "0 - Sair"
		echo -e "\n"
		read texto

		if [ "$texto" = "1" ]
			then
		    	sudo rm -rf $pasta_saida
		    	echo "Pasta removida com sucesso."
		    	clear
		else
			exit 1 
		fi
	fi 



#criar estrutura de pastas
eval "sudo mkdir -p $pasta_saida/{files/,hosts/,reports/html,protocolos/,equipamentos/,captura/,email/,sessoes/,ligacoes/,hashs/,portos/,pesquisa/}"


#validar argumentos de entrada e ficheiro pcap
if [ "$#" -ne "$numero_argumentos" ];then
	echo  "Numero de argumentos invalidos. Tente ./<nome_do_script> <ficheiro_pcap> <pasta_de_saida>"
	exit 1
else
	if [ ! -f $(basename "$1") ]; 
	then 
		echo  "O ficheiro PCAP nao existe"
		exit 1 
	fi 
fi


#verificar se falta alguma app a instalar
for r in $aplicacoes
	do
	   if ! which $r >/dev/null; then
	   echo -e "Aplicação $r não instalada ..."
	   read -rsp $'Press enter to continue...\n'
	   sudo yum install $r || sudo apt-get install $r  
	fi
done


#separar os link e criar uma nova pagina com todos
function separar(){
	STR=$1
	link='';
	STR_ARRAY=(`echo $STR | tr ";" "\n" | sort -u`)
	for x in "${STR_ARRAY[@]}"
	do
		link+="<a href = '../$x' target = '_parent'>$x - <b> Clique Aqui Ver</b></a><br/><br/>"
	done
	pagina_html="<HTML>
			    <HEAD>
				<TITLE>
				Todos os elementos
				</TITLE>
				<meta charset='UTF-8'>
			    </HEAD>
			    <BODY>
				<div style = 'witdh = 100%; text-align: center;'><i>Resumo de Informação</i></div>
				$link
			    </BODY>
			</HTML>"

	#colocar todos os link nas raiz
	echo $pagina_html > "$pasta_saida/index.html"
	echo -e "\n"
	echo "Consulte as informações em: '$pasta_saida/index.html'"	
}




#recebe: titulo - comando - caminho - nome_txt - colocar_enter(1-sim/0-nao) 
function gerar_html(){
	OUTPUT='';
	META='';
	if [ "$5" = "1" ]
	then
	   	aux_array=( $($2) )
		for (( i=0; i<${#aux_array[@]}; i++ )); 
			do OUTPUT+=${aux_array[i]}'<br/>';
		done
		total_res=${#aux_array[@]}
		OUTPUT="<b>Total de Resultados: <i>$total_res</i> </b><br/><a href = '$4.txt' target = '_parent'>Para melhor visualização <b>Clique Aqui </b></a><br/><br/>$OUTPUT"
	else
	    	OUTPUT="<a href = '$4.txt' target = '_parent'>Para melhor visualização <b>Clique Aqui </b></a><br/><br/>"$($2)
		META='<meta http-equiv="refresh" content="0;URL='$4'.txt" />' #caso os resultados em html não sejam legíveis reencaminha para o txt
	fi
	
	pagina_html="<HTML>
			    <HEAD>
				<TITLE>
				$1
				</TITLE>
				<meta charset='UTF-8'>
				$META
			    </HEAD>

			    <BODY>
				$OUTPUT
			    </BODY>
			</HTML>"

	#guardar link
	todos_html+="$3.html;"

	#escrever para o ficheiro
	echo $pagina_html > "$3.html"
	
	#criar pagina com todos os link
	separar $todos_html
}


#listar todos os hosts
function f_lista_de_hosts(){
	echo $aguarde
	echo -e "IPV4"
	tshark -r $ficheiro_pcap -q -z hosts,ipv4 | tee $ficheiro_hosts_ipv4
	echo -e "\n\n IPV6"
	tshark -r $ficheiro_pcap -q -z hosts,ipv6 | tee $ficheiro_hosts_ipv6
	echo -e "\n"

	#gerar html
	gerar_html "IPV4" "tshark -r $ficheiro_pcap -q -z hosts,ipv4" "$ficheiro_hosts_ipv4" "hosts_ipv4" "1"
	gerar_html "IPV6" "tshark -r $ficheiro_pcap -q -z hosts,ipv6" "$ficheiro_hosts_ipv6" "hosts_ipv6" "1"
}

#Todos os equipamentos
function f_equipamentos_de_rede(){
	echo $aguarde
	tshark -r $ficheiro_pcap -T fields -e ip.src |sort |uniq |tr , '\n' | sort | uniq | tee -a $ficheiro_equipamentos_rede
	
	#gerar html
	gerar_html "Todos os equipamentos" "" "$ficheiro_equipamentos_rede" "equipamentos" "0"

	echo -e "Total de IPS: $(expr $(cat $ficheiro_equipamentos_rede |wc -l) - 1)"
}

#Protocolos e Serviços na Rede
function f_protocolos_servicos_rede() {
	echo $aguarde
	tshark -r $ficheiro_pcap -q -z io,phs | tee -a $ficheiro_protocolos

    echo -e "\n"
	tshark -r $ficheiro_pcap -q -z ptype,tree
	
	#gerar html
	gerar_html "Protocolos" "" "$ficheiro_protocolos" "protocolos" "0"
}

#Ficheiros presentes na captura (Carving)
function f_ficheiros_presentes() {
	echo $aguarde
	echo -e "\n"
	rm -r $pasta_ficheiros_extraidos/*
	foremost -v -i $ficheiro_pcap -o $pasta_ficheiros_extraidos
	sudo chmod 777 $pasta_ficheiros_extraidos/*
}

#Reports html
function f_reports_html(){
	echo $aguarde
	chaosreader $ficheiro_pcap  -D $pasta_reports
	#xdg-open $ficheiro_html_reports 
	todos_html+="$pasta_reports/index.html;"
	separar $todos_html

}

#funções para mostrar informações sobre os emails
function f_emails () {
	echo $aguarde
	ngrep -q -I $ficheiro_pcap '[a-zA-Z0-9.]+\.?@[a-zA-Z0-9.]+\.[a-zA-Z0-9]+' |grep -Eo '[a-zA-Z0-9.]+\.?@[a-zA-Z0-9.]+\.[a-zA-Z0-9]+'|sort|uniq | tee $ficheiro_email
	echo "E-mails recolhidos com sucesso."

	#gerar html
	gerar_html "Email" "" "$ficheiro_email" "email" "0"
}

#Informações da captura 
function f_informacao () {
	echo $aguarde
	capinfos $ficheiro_pcap | tee $ficheiro_informacao_captura
	
	#gerar html
	gerar_html "Informação Captura" "" "$ficheiro_informacao_captura" "informacao_captura" "0"
}

#Sessões de rede
function f_sessoes () {
	echo $aguarde
	tcptrace -q -xcollie $ficheiro_pcap > $ficheiro_sessoes
	
	#gerar html
	gerar_html "Sessões de Rede" "" "$ficheiro_sessoes" "sessoes_captura" "0"
}

#Ligacoes por protocolo (conversations)
function f_ligacoes() {
	echo $aguarde
	echo -e "\nLigacoes Protocolo :Ethernet\n"
	tshark -r $ficheiro_pcap  -q -z conv,eth | tee $ficheiro_ligacoes_ethernet
	gerar_html "Ligacoes Protocolo :Ethernet" "" "$ficheiro_ligacoes_ethernet" "ethernet" "0"

	echo -e "\nLigacoes Protocolo :IPV4 e IPV6\n"
	tshark -r $ficheiro_pcap -q -z conv,ipv4 -z conv,ipv6 | tee $ficheiro_ligacoes_ipv4e6
	gerar_html "Ligacoes Protocolo :IPV4 e IPV6" "" "$ficheiro_ligacoes_ipv4e6" "ipv4e6" "0"

	echo -e "\nLigacoes Protocolo :TCP\n"
	tshark -r $ficheiro_pcap -q -z conv,tcp | tee $ficheiro_ligacoes_tcp
	gerar_html "Ligacoes Protocolo :TCP" "" "$ficheiro_ligacoes_tcp" "tcp" "0"

	echo -e "\nLigacoes Protocolo :UDP\n"
	tshark -r $ficheiro_pcap -q -z conv,udp | tee $ficheiro_ligacoes_udp
	gerar_html "Ligacoes Protocolo :UDP" "" "$ficheiro_ligacoes_udp" "udp" "0"
		
}


#Top 5 Talkers por protocolo
function f_equipamentosTOP5() { # equipamentos mais usados por protocolo
	echo $aguarde
	echo -e "\n5 Equipamentos Mais Usados\n"
	tcpdump -tnr $ficheiro_pcap |awk -F '.' '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -n |tail -n 5 | tee $ficheiro_top_equipamentos
	gerar_html "5 Equipamentos Mais Usados" "" "$ficheiro_top_equipamentos" "TopEquipamentos" "0"

	echo -e "\n5 Equipamentos Mais Usados - Protocolo IP"
	tcpdump -tnr $ficheiro_pcap ip |awk -F '.' '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -n |tail -n 5 | tee $ficheiro_top_equipamentos_ipv4e6
	gerar_html "5 Equipamentos Mais Usados - Protocolo IP" "" "$ficheiro_top_equipamentos_ipv4e6" "TopIPV4eIPV6" "0"

	echo -e "\n5 Equipamentos Mais Usados - Protocolo TCP"
	tcpdump -tnr $ficheiro_pcap tcp |awk -F '.' '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -n |tail -n 5 | tee $ficheiro_top_equipamentos_tcp
  	gerar_html "5 Equipamentos Mais Usados - Protocolo TCP" "" "$ficheiro_top_equipamentos_tcp" "TopTcp" "0"

  	echo -e "\n5 Equipamentos Mais Usados - Protocolo UDP"
  	tcpdump -tnr $ficheiro_pcap udp |awk -F '.' '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -n |tail -n 5 | tee $ficheiro_top_equipamentos_udp
	gerar_html "5 Equipamentos Mais Usados - Protocolo UDP" "" "$ficheiro_top_equipamentos_udp" "TopUdp" "0"
}


#Portos usados
function f_portos_usados() {
	echo $aguarde
	tshark -o gui.column.format:'"Source", "%s", "Destination","%d", "dstport", "%uD"' -r $ficheiro_pcap |sort|uniq | tee $ficheiro_portos

    #gerar html
	gerar_html "Portos Usados" "" "$ficheiro_portos" "portos" "0"

}


#Procurar String
function f_procura_string() {
	echo -e "\n Introduza a string a pesquisar\n"
	read string
	echo -e "\n"
	echo $aguarde
	ngrep -q -I $ficheiro_pcap|grep -i $string | tee "$pasta_pesquisa/$string.txt"

    #gerar html
    gerar_html "Pesquisas" "" "$pasta_pesquisa/$string.txt" "$string" "0"
	

}


#Criar hashs
function f_criar_hashs(){
	echo $aguarde

    echo -e "\nMD5"
	md5sum $ficheiro_pcap > "$pasta_hashs/$ficheiro_pcap.md5"
 	md5sum -c "$pasta_hashs/$ficheiro_pcap.md5" #validar integridade do ficheiro

    echo -e "\nSHA1"
	sha1sum $ficheiro_pcap > "$pasta_hashs/$ficheiro_pcap.sha1"
	sha1sum -c "$pasta_hashs/$ficheiro_pcap.sha1" #validar integridade do ficheiro


    echo -e "\nSHA256"
	sha256sum $ficheiro_pcap > "$pasta_hashs/$ficheiro_pcap.sha256" 
	sha256sum -c "$pasta_hashs/$ficheiro_pcap.sha256" #validar integridade do ficheiro

	echo -e "\nSHA512"
	sha512sum $ficheiro_pcap > "$pasta_hashs/$ficheiro_pcap.sha512" 
	sha512sum -c "$pasta_hashs/$ficheiro_pcap.sha512" #validar integridade do ficheiro
}

#menu
PS3='Introduza uma opção: '
options=( "Informação da Captura" "Lista de Hosts" "Todos os equipamentos" "Ligacoes por Protocolo" "Equipamentos mais usados" 
	"Protocolos e Serviços na Rede" "Portos Usados" "Ficheiros presentes na captura (Carving)" "Report HTML" "Encontrar E-mails"
	"Encontrar String" "Sessões de Rede" "Criar Hashs" "Sair")
select opt in "${options[@]}"
do
    case $opt in
	"Informação da Captura")
		f_informacao 
		;;
	"Lista de Hosts")
		f_lista_de_hosts 
		;;
	"Todos os equipamentos")
		f_equipamentos_de_rede 
		;;
	"Ligacoes por Protocolo")
		f_ligacoes
		;;
	"Equipamentos mais usados")
		f_equipamentosTOP5
		;;
	"Protocolos e Serviços na Rede")
		f_protocolos_servicos_rede 
		;;  
	"Portos Usados")
		f_portos_usados
		;;  
	"Ficheiros presentes na captura (Carving)")
		f_ficheiros_presentes 
		;;
	"Report HTML")
		f_reports_html 
		;; 
	"Encontrar E-mails")
		f_emails 
		;;
	"Encontrar String")
		f_procura_string 
		;;
	"Sessões de Rede")
		f_sessoes 
		;;
	"Criar Hashs")
		f_criar_hashs
		;;
	"Sair")
		break
		;;
        *) echo "Opção inválida...";;
    esac
done













