- [Análise da campanha](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Análise-da-campanha)
  -   [Repellent Scorpius](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Repellent-Scorpius)
	- [LummaC2 Stealer](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#LummaC2-Stealer)
	- [Cicada3301](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Cicada3301)
- [Cyber Kill Chain](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Cyber-Kill-Chain)
- [Diamond Model](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Diamond-Model)
- [Contenção](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Contenção)
- [Correlacionando tráfego de rede com arquivos suspeitos](https://github.com/willyamcts/report-ir/blob/main/relacionados_campanha.md#Correlacionando-tráfego-de-rede-com-arquivos-suspeitos)

                                                           
# Análise da campanha

https://www.safebreach.com/blog/cicada3301-ransomware-lummac2-infostealer-threat-coverage/

O incidente observado faz parte de uma campanha de ransomware coordenada por afiliados do grupo Cicada3301. O acesso inicial ao ambiente foi obtido via Lumma Stealer (LummaC2), um ladrão de informações (infostealer) fornecido no modelo Malware as a Service utilizado para exfiltração de dados, incluindo credenciais, histórico, cookies, carteiras de criptomoedas (tal como Binance, Electrum e Ethereum) e dados de extensões 2FA (Fonte: Cyble)

O LummaC2  é um malware vendido em fóruns underground como Malware as a Service (MaaS), ou seja, ele adquirido em formato de malware como serviço, o qual possui uma infraestrutura command-and-control (C2) para o atacante fazer a exfiltração dos dados da vítima de forma criptografada. Emprega técnicas avançadas de ofuscação, evasão e anti-sandbox para dificultar sua análise. A execução do Lumma ocorre em memória sem arquivos, dificultando a detecção por ferramentas de segurança (Fonte: Outpost24). A técnica anti-sandbox empregada, força o malware a aguardar até que um comportamento humano seja detectado, a partir da movimentação realista do mouse (Fonte: Cyber Security Brazil).


## Repellent Scorpius

Links
* https://unit42.paloaltonetworks.com/repellent-scorpius-cicada3301-ransomware/
* https://thecyberthrone.in/2024/09/10/repellent-scorpius-raas-dissection/

Repellent Scorpius é o grupo por trás do RaaS conhecido como Cicada3301. O grupo fornece Cicada3301 em formato de serviço, ou seja, Ransomware as a Service (RaaS). O início das atividades do grupo ocorreu por volta de maio de 2024, em julho de 2024 em um site o grupo publicou os dados exfiltrados de algumas empresas que não pagaram o resgate.

O grupo visa empregar a dupla extorsão com criptografia, onde é solicitado um resgate para descriptografar os dados ou para não divulgar os dados exfiltrados

Considerando que a mensagem de resgate está em nome do grupo Cicada3301, este utiliza do LummaC2 Stealer para exfiltração dos dados da vítima para futura extorsão financeira caso o resgate dos dados criptografados seja negado. Dessa forma, é visto que o grupo Cicada3301 utiliza a infraestrutura maliciosa do LummaC2 como serviço, um para exfiltração de dados da vítima e posteriormente, por conta própria aplica a criptografia nos arquivos da vítima, que caracteriza o ataque de ransomware.


O grupo **Repellent Scorpius** é responsável por distribuir o ransomware Cicada3301 em formato de serviço, ou seja, Ransomware as a Service (RaaS). O início das atividades do grupo ocorreu por volta de maio de 2024, em julho de 2024 em seu site **cicadabv7vicyvgz5khl7v2x5yygcgow7ryy6yppwmxii4eoobdaztqd[.]onion** o grupo começou publica os dados exfiltrados das vítimas que não pagaram o resgate (Fonte: [Vipre](https://vipre.com/blog/cicada3301-ransomware-operation-encryption)).

O foco do grupo não possui setores específicos, até o momento os alvos foram de diversos setores, abrangendo desde o setor de serviços bancários, financeiros e seguros, governo, produtos farmacêuticos e manufatura, telecomunicações, TI, e até mesmo agricultura e pecuária. Além de não ter países alvos específicos, apenas proíbe ataques em países que compõem a Comunidade dos Estados Independentes – CIS (Fonte: [Palo Alto Netoworks](https://unit42.paloaltonetworks.com/repellent-scorpius-cicada3301-ransomware/)).

O principal vetor de acesso ao alvo é a partir de credenciais comprometidas ou de força bruta em sistemas de autenticação, além de possuir uma botnet conhecida como Brutus capaz de adivinhar senhas e explorar vulnerabilidades do sistema. Ao ser executado estabelece comunicação com C2 por meio de túnel SSH reverso, e ferramentas como Plink, GOST e proxy SOCKS (Fonte: [Palo Alto Networks](https://unit42.paloaltonetworks.com/repellent-scorpius-cicada3301-ransomware/))

Acredita-se que o grupo é de algum dos países da antiga União das Repúblicas Socialistas Soviéticas (URSS) e não permite o uso do ransomware em países que faziam parte da URSS.


## LummaC2 Stealer

Durante a análise foi possível identificar que o malware se trata de um infostealer chamado Lumma Stealer, também conhecido como LummaC2 Stealer. O principal Indicador de Comprometimento (IoC) do incidente foi a comunicação com o domínio **latesttributedowps.shop** (IPs 172.67.138.40 e 104.21.70.178), um dos IoCs que compõem a infraestrutura do Lumma Stealer.


O LummaC2 Stealer é um malware vendido em fóruns underground desde dezembro de 2022, como Malware as a Service (MaaS), ou seja, ele é oferecido mediante a assinatura como serviço, disponível em diferentes planos onde cada um oferecem diferentes recursos aos usuários, como acesso a um painel de comando e controle (C2) que permite monitorar e gerenciar atividades das vítimas focado em sistemas operacionais Windows (Fonte: [ANY.RUN](https://anyrun.de/malware-trends/lumma/)).

Alguns recursos do Lumma incluem:
* exfiltração de dados, incluindo credenciais, histórico, cookies, credenciais, carteiras de criptomoedas (tal como Binance, Electrum e Ethereum) e dados de extensões 2FA (Fonte: [Cyble](https://cyble.com/blog/lummac2-stealer-a-potent-threat-to-crypto-users/))
* atualização regular
* coleta de logs do endpoint infectado
* permite a instalação de malware adicional nas máquinas infectadas
* criptografia dos dados exfiltrados para dificultar a identificação das atividades
Fonte: [ANY.RUN](https://anyrun.de/malware-trends/lumma/)

Os métodos de distribuição do malware incluem principalmente através de software falso e e-mail phishing (Fonte: [ANY.RUN](https://anyrun.de/malware-trends/lumma/)).

O LummaC2 possui técnicas avançadas de ofuscação, evasão e anti-sandbox para dificultar sua análise. A execução do Lumma ocorre em memória, sem arquivos, dificultando a detecção por ferramentas de segurança (Fonte: [Outpost24](https://outpost24.com/blog/everything-you-need-to-know-lummac2-stealer/)). A técnica anti-sandbox empregada, força o malware a aguardar até que um comportamento humano seja detectado, a partir da movimentação realista do mouse (Fonte: [Cyber Security Brazil](https://www.cybersecbrazil.com.br/post/malware-lummac2-usa-trigonometria-para-evitar-an%C3%A1lises-automatizadas-em-solu%C3%A7%C3%B5es-sandbox)). Além disso, tem sido utilizado em conjunto com outros malwares e campanhas de ransomware e apresentado alta capacidade de integrações e designer modular para integrar partes mais complexas para determinados alvos (Fonte: [Outpost24](https://outpost24.com/blog/everything-you-need-to-know-lummac2-stealer/))



o qual possui uma infraestrutura command-and-control (C2) para o atacante fazer a exfiltração dos dados da vítima de forma criptografada. Esse malware não possui mecanismo de persistência, o foco é apenas coletar e exfiltrar os dados durante a sessão ativa (Fonte: [UnpacMe](https://www.unpac.me/results/2f24d9f3-2503-4248-ab35-9949b42ad967)).


Links:
* https://anyrun.de/malware-trends/lumma
* https://www.cybersecbrazil.com.br/post/malware-lummac2-usa-trigonometria-para-evitar-an%C3%A1lises-automatizadas-em-solu%C3%A7%C3%B5es-sandbox
* https://outpost24.com/blog/everything-you-need-to-know-lummac2-stealer/
* https://www.safebreach.com/blog/cicada3301-ransomware-lummac2-infostealer-threat-coverage/
* https://cyble.com/blog/lummac2-stealer-a-potent-threat-to-crypto-users/
* https://cyble.com/blog/threat-actor-targets-manufacturing-industry-with-malware/
* https://cyble.com/blog/lummac-stealer-leveraging-amadey-bot-to-deploy-sectoprat/


## Cicada3301

Links:
* https://cyble.com/threat-actor-profiles/cicada3301/
* https://vipre.com/blog/cicada3301-ransomware-operation-encryption
* https://unit42.paloaltonetworks.com/threat-actor-groups-tracked-by-palo-alto-networks-unit-42/
* https://www.group-ib.com/blog/cicada3301/
* https://www.quorumcyber.com/threat-actors/cicada3301-threat-actor-profile/
* https://www.ransomware.live/group/cicada3301
* https://www.cisoadvisor.com.br/grupo-de-ransomware-ataca-usando-cicada3301/
* https://malpedia.caad.fkie.fraunhofer.de/details/win.cicada3301


* Fonte: https://vipre.com/blog/cicada3301-ransomware-operation-encryption
	* o acesso ao alvo é feito a partir de credenciais comprometidas ou de força bruta em sistemas de autenticação, além de possuir uma botnet conhecida como Brutus capaz de adivinhar senhas e explorar vulnerabilidades do sistema

* Fonte: https://unit42.paloaltonetworks.com/repellent-scorpius-cicada3301-ransomware/
	* cobra 20% dos lucros obtidos no uso do seu RaaS
	* suas atividades indicam que iniciaram as atividades em maio de 2024
	* o grupo emprega a dupla extersão com criptografia, onde é solicitado um resgate para descriptografar os dados ou para não divulgar os dados exfiltrados
	* o grupo se comunica em fóruns para recrutamento em linguagem russa
	* não possui países específicos como alvo, apenas não permite ataque a países que compõem o CIS (Comunidade dos Estados Independentes), composto por Armênia, Azerbaijão, Bielorrússia, Cazaquistão, Quirguistão, Moldávia, Rússia, Tajiquistão, Turcomenistão, Ucrânia e Uzbequistão
	* não possui foco em determinados setores, até o momento já foram diversos setores, abrangendo desde o setor de serviços bancários, financeiros e seguros, governo, produtos farmacêuticos e manufatura, telecomunicações, TI, e até mesmo agricultura e pecuária.
	* utiliza ferramentas como Mimikatz para extração de credenciais, além de fazer uso de credenciais vazadas e brute force
	* cria múltiplas tarefas para serem executadas a cada hora comandos diferentes
	* utiliza ferramentas como ADRecon, wmic, ping, ipconfig, net e quser para descoberta de ativos e contas
	* ao ser executado estabelece comunicação com C2 por meio de túnel SSH reverso, e ferramentas como Plink, GOST e proxy SOCKS


**Infraestrutura do Cicada3301:**
- 103.42.240[.]37 - server RDP, executa tentativas de conexão RDP
- 91.238.181[.]238 -  IP address attackers used for exfiltration activity.
- cicadabv7vicyvgz5khl7v2x5yygcgow7ryy6yppwmxii4eoobdaztqd[.]onion/

Fonte: https://unit42.paloaltonetworks.com/repellent-scorpius-cicada3301-ransomware/




# Cyber Kill Chain
https://unit42.paloaltonetworks.com/repellent-scorpius-cicada3301-ransomware/
O presente incidente seguiu as etapas típicas descritas pelo modelo Ciber Kill Chain, que permite uma compreensão sucinta e direta, ajudando a identificar os pontos cruciais para a segurança da informação. A seguir é descrito o ataque em cada uma das fases do modelo:

1. Na fase de reconhecimento, os atacantes mapearam sites de streaming pirata com grande volume de tráfego e vulneráveis a injeção de JavaScript malicioso, considerando o perfil de vítimas com pouco conhecimento em segurança em busca de conteúdo gratuito.
2. Na fase de armamento, o atacante criou páginas maliciosas com cadeia de redirecionamentos JavaScript ofuscados, projetados para redirecionar o usuário a um site com instruções de engenharia social para execução manual de comandos ofuscados em PowerShell.
3. Entrega. A entrega depende da ação do usuário, onde ele acessa tucinehd.com > clica para assistir > sequência de requisições JavaScript com redirecionamento > chega a uma página falsa que exibe passos a serem realizados que inclui copiar um código e colar no PowerShell em modo administrador. O comando PowerShell baixa e executa o Lumma Stealer (omgsoft.exe).
4. Exploração: Ao colar o comando no PowerShell, é baixado o Lumma Stealer enquanto a sessão estiver ativa. Essa exploração é baseada em comportamento humano e uso legítimo do PowerShell, sem exploração de vulnerabilidades tradicionais.
5. Instalação: A instalação e persistência ocorre apenas com Cicada3301. O LummaC2 não instala e não tem persistência, ainda assim pode se manter conectado ao C2 enquanto a sessão estiver ativa.
6. Comando e Controle (C2): Enquanto o processo estiver ativo, é exfiltrado informações para domínios dinâmicos como *.shop e *.lol, usando HTTPS/TLS em portas comuns, além de criptografar as informações coletadas.
7. Ações: Lumma rouba cookies, senhas, carteiras de criptomoedas e tokens de autenticação e realiza a exfiltração dos dados. Com as credenciais roubadas, um afiliado ao Cicada3301 realiza o acesso à infraestrutura, criptografando os sistemas críticos e exigindo resgate.


# Diamond Model
https://www.eccouncil.org/cybersecurity-exchange/ethical-hacking/diamond-model-intrusion-analysis/

* É um framework que auxilia a análise de intrusões.
* O objetivo principal é identificar atacantes e entender a táticas, ameaças e procedimentos que são utilizados a fim de responder de forma mais eficaz a incidentes a medida que ocorrem
* O framework permite identificar, mapear e relacionar os componentes envolvidos em um incidente de forma simplificada (Figura 18).

![[images/cenario9-DIAMOND.png]]



# Contenção

Após identificar o ataque, que teve vetor inicial engenharia social através de um site malicioso, a PROSec em conjunto com a equipe de TI iniciou uma série de ações para interromper a propagação do malware, mitigar os danos e prevenir novas ocorrências.

O ambiente inicialmente afetado pelo ataque foi isolado para evitar propagação na rede e as comunicações com servidores command-and-control foram interrompidas diretamente no firewall.

Foi habilitado recursos de anti-malware inspection e IPS para análise do tráfego no firewall, além do application control para restringir o acesso dos usuários a determinadas categorias de site como conteúdo de pirataria/ilegal e criptomoedas.

Como meios de correção e prevenção foram aplicadas as seguintes medidas:
- removido os usuários que pertenciam ao grupo de administradores e não precisavam de tal permissão para desempenhar as atividades
- redefinido a senha dos usuários que foram afetados e dos demais pertencentes ao grupo de administrador
- orientado os usuários do grupo administrador a não reutilizar a senha
- removido as permissões de administrador local nas máquinas via GPO
- mapeado os sistemas e ferramentas desatualizadas e iniciado aplicação dos patches necessários para evitar outros vetores de ataque
- aplicado GPO para restringir a execução do CMD e PowerShell apenas para usuários do grupo de administradores
- aplicado GPO para bloquear a execução de scripts via CMD e PowerShell

Além disso, foi implementado um sistema de monitoramento contínuo de rede, que possibilita a identificação de atividades suspeitas na rede, gerando alertas e relacionando eventos relacionados a padrões de comportamento malicioso.

Em conjunto com a equipe de TI foi elaborado um programa de conscientização para os colaboradores, focado em cuidados e práticas seguras para identificar possíveis agentes maliciosos e a importância do sigilo e da unicidade de credenciais, buscando reduzir a probabilidade de sucesso de ataques futuros.

Todas as evidências coletadas foram documentadas e analisadas, estas nos permitem vincular diretamente o vetor de ataque inicial e o comprometimento do ambiente. Além das medidas de contenção e erradicação implementadas, é necessário o monitoramento constante do ambiente para garantir a confidencialidade, integridade e disponibilidade.





-----------

