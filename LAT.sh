#!/bin/bash

# Help
#		https://www.networkworld.com/article/3143050/linux/linux-hardening-a-15-step-checklist-for-a-secure-linux-server.html
#		https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
#		#http://davemacaulay.com/easily-test-dirty-cow-cve-2016-5195-vulnerability/

header()
	{
		echo -e "\n\e[00;31m#########################################################\e[00m" 
		echo -e "\e[00;31m#####\e[00m" "\e[00;33m            LINUX AUDITING TOOL              \e[00m" "\e[00;31m#####\e[00m"
		echo -e "\e[00;31m#########################################################\e[00m"
		date=`date`
		echo -e "\n\e[1;33mScan started at: $date\e[00m\n" 
		
	}

system_info()
	{
		#basic kernel info
		kernelinfo=`cat /proc/version 2>/dev/null`
		if [ "$kernelinfo" ] ; then
			echo -e "[+] \e[1;4;37mKernel information:\e[00m \e[00;36m\n\t$kernelinfo\e[00m" 
			echo -e "\n"
		else 
			:
		fi

		#target hostname info
		hostname=`hostname 2>/dev/null`
		if [ "$hostname" ]; then
		 	echo -e "[+] \e[1;4;37mHostname:\e[00m \e[00;36m\n\t$hostname\e[00m" 
		 	echo -e "\n"
		else 
			:
		fi
	}

user_info()
	{
		#Admin users information
		adm_users=$(echo -e "$grpinfo" | grep "(adm)")
		if [[ ! -z $adm_users ]];
		  then
		    echo -e "[+] \e[1;4;37mAdmin users:\e[00m"
		    while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $adm_users
		    echo -e "\n"
		else 
			:
		fi

		#all root accounts (uid 0)
		rootaccount=`grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null`
		if [ "$rootaccount" ]; then
		  	echo -e "[+] \e[1;4;37mSuper user account(s):\e[00m"
			while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $rootaccount
		 	echo -e "\n"	
		else
			:
		fi

		sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" | sed 'N;s/\n/,/' 2>/dev/null`
		if [ "$sudoers" ]; then
		  	echo -e "[+] \e[1;4;37mSuper user account(s):\e[00m"
			while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $sudoers
		 	echo -e "\n"
		else 
		  :
		fi		
	}

file_system()
	{
		#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
		hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
		echo -e "[+] \e[1;4;37mCheck passwd file:\e[00m"
		if [ "$hashesinpasswd" ]; then
		  	echo -e "\e[1;31m\tHashes stored in this file\e[00m\n" 
		else 
			echo -e "\e[1;32m\tNo hashes in this file\e[00m\n"
		fi

		#checks to see if the shadow file can be read by users
		readshadow=`ls -la /etc/shadow | grep -v "\-rw-------" 2>/dev/null`
		echo -e "[+] \e[1;4;37mCheck shadow file:\e[00m"
		if [ "$readshadow" ]; then
		  	echo -e "\e[1;31m\tShadow file permissions doesn't respect best practice. (chmod 600 /etc/shadow) \e[00m\n" 
		else 
		 	echo -e "\e[1;32m\tShadow file respect best practice\e[00m\n"
		fi

		#list of suid file
		#http://www.filepermissions.com/directory-permission/
		binaries='nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|emacs\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|tar\|zip\|gdb\|pico\|scp\|git\|rvim\|script\|ash\|csh\|curl\|dash\|ed\|env\|expect\|ftp\|sftp\|node\|php\|rpm\|rpmquery\|socat\|strace\|taskset\|tclsh\|telnet\|tftp\|wget\|wish\|zsh\|ssh'
		echo -e "[+] \e[1;4;37mSUID files:\e[00m"
		suid=`find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binaries 2>/dev/null`
		if [ "$suid" ]; then
			while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $suid
		  	echo -e "\n"			
		else 
			echo -e "\e[1;32m\tNo SUID files existing\e[00m\n"
		fi

		#list of guid files
		#http://www.filepermissions.com/directory-permission/
		echo -e "[+] \e[1;4;37mGUID files:\e[00m" 
		guid=`find / -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binaries 2>/dev/null`
		if [ "$guid" ]; then
			while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $guid
			echo -e "\n" 
		else 
			echo -e "[+] \e[1;4;37mGUID files: \e[00m \e[1;32m\n\tNo GUID files existing\e[00m"
			echo -e "\n"
		fi

		#list of interesting files
		echo -e "[+] \e[1;4;37mInteresting files:\e[00m"
		interestingfile=`find . \( -name "*.php" -o -name "*.bdd"  -o -name "*.sql" \) -exec ls -la {} \;`
		if [ "$interestingfile" ]; then
			while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $interestingfile
			echo -e "\n" 
		else 
			echo -e "[+] \e[1;4;37mInteresting files: \e[00m \e[1;32m\n\tNo interesting files existing\e[00m"
			echo -e "\n"
		fi

		#looking for credentials in /etc/fstab
		fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
		fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
		echo -e "[+] \e[1;4;37mCheck FSTAB files:\e[00m"
		if [ "$fstab" ] || [ "$fstabcred" ]; then
		  	echo -e "\e[1;31m\tCredentials found in FSTAB\e[00m\n"
		 else 
		  	echo -e "\e[1;32m\tNo credential in this file\e[00m\n"

		fi

		#extract any user history files that are accessible
		userhistory=`ls -la ~/.*_history 2>/dev/null`
		echo -e "[+] \e[1;4;37mHistory available:\e[00m"
		if [ "$userhistory" ]; then
		 	echo -e "\e[1;31m\tHistory file existing\e[00m\n"
		else 
		  	echo -e "\e[1;32m\tHistory file not existing\e[00m\n"
		fi
	}

conf()
	{
		deprecated_encryption='MD5\|SHA1'
		#password policy information as stored in /etc/login.defs
		timestoragepwd=`grep "^PASS_MAX_DAYS" /etc/login.defs | awk -F ' ' '{print $2}' 2>/dev/null`
		encryptionpwd=`grep "^ENCRYPT_METHOD" /etc/login.defs | awk -F ' ' '{print $2}' 2>/dev/null`
		if [ "$timestoragepwd" ]; then
			echo -e "[+] \e[1;4;37mExiration password:\e[00m"
			if [ $timestoragepwd -gt 90 ]; then
		  		echo -e "\e[1;31m\t$timestoragepwd => This configuration doesn't respect best pratices\e[00m\n"
		  	else
		  		echo -e "\e[1;32m\t$timestoragepwd\e[00m\n"
		  	fi
		else
			echo -e "\e[00;36m\tInfo not available\e[00m\n"
		fi

		if [ "$encryptionpwd" ]; then
			echo -e "[+] \e[1;4;37mEncryption used:\e[00m"
			if [ $(echo $deprecated_encryption | grep $encryptionpwd) ]; then
				echo -e "\e[1;31m\t$encryptionpwd => This encryption is deprecated\n"
			else
				echo -e "\e[1;32m\t$encryptionpwd\e[00m\n"
			fi
		else 
		  	echo -e "\e[00;36m\tInfo not available\e[00m\n"
		fi

		open_port=` netstat -tupln | grep -v p6`
		if [ "$open_port" ]; then
			echo -e "[+] \e[1;4;37mPort(s) open:\e[00m"
			while read -r line; do
				echo -e " \e[00;36m\t$line\e[00m" 
			done <<< $open_port
			echo -e "\n"
		else
			echo -e " \e[00;36m\tInformation not available\e[00m" 
		fi

		#Check SSH configuration
		sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
		echo -e "[+] \e[1;4;37mRoot is allowed to login via SSH:\e[00m"
		if [ "$sshrootlogin" = "yes" ]; then
		  	echo -e "\e[1;31m\tRoot login is enable => this configuration doesn't respect best practice\e[00m\n"
		else 
		   	echo -e "\e[1;32m\tRoot login has been disabled\e[00m\n"
		fi

		sshdefaultport=`cat /etc/ssh/sshd_config  | grep "^Port 22" | awk '{print  $2}'`
		echo -e "[+] \e[1;4;37mSSH default port:\e[00m"
		if [ "$sshdefaultport" = "22" ]; then
		  	echo -e "\e[1;31m\tSSH use default port configuration => this configuration doesn't respect best practice\e[00m\n"
		else 
		   	echo -e "\e[1;32m\tSSH port is listening on $sshdefaultport\e[00m\n"
		fi

		sshrights=`ls -la /etc/ssh/sshd_config | grep -v "\-rw-------" 2>/dev/null`
		sshowner=`ls -la /etc/ssh/sshd_config | awk '{print  $3}'`
		sshgrp=`ls -la /etc/ssh/sshd_config | awk '{print  $4}'`
		echo -e "[+] \e[1;4;37mSSH permissions file:\e[00m"
		if [ "$sshowner" != "root" ]; then
		  	echo -e "\e[1;31m\tSSH configuration file must belong to root user => this doesn't respect best practice\e[00m\n"
		elif [ "$sshgrp" != "root" ]; then
		   	echo -e "\e[1;31m\tSSH configuration file must belong to root group => this doesn't respect best practice\e[00m\n"
		elif [ "$sshrights" ]; then
			echo -e "\e[1;31m\tSSH file permissions doesn't respect best practice. (chmod 600 /etc/ssh/sshd_config) \e[00m\n"
		else
			echo -e "\e[1;32m\tSSH file is well configured \e[00m\n"
		fi


	}

exploit()
	{
		echo -e "[+] \e[1;4;37mCheck shellshock vulnerability\e[00m"
		shelly=`env x='() { :;}; echo 1; exit;' bash -c 'echo 0' 2>/dev/null`
		if [ $shelly = "1" ]; then
			echo -e "\e[1;31m\tVulnerable to shellshock\e[00m\n"
		else
			echo -e "\e[1;32m\tNot vulnerable to shellshock\e[00m\n"
		fi
		echo -e "\n"


		echo -e "[+] \e[1;4;37mCheck Dirty C0w vulnerability\e[00m"

		if [[ $EUID -ne 0 ]]; then
		   echo -e "This script must be run as root\n"
		else
		    # Download the exploit
		    curl -s https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c > dirtyc0w.c

		    # Check our file downloaded
		    if [ ! -f dirtyc0w.c ]; then
		        echo -e "Unable to download dirtyc0w.c from https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c\n"
		    else
		        # Create a new temporary test file to test with
		        echo ORIGINAL_STRING > dirtycow_test
		        chmod 0404 dirtycow_test

		        gcc -pthread dirtyc0w.c -o dirtyc0w

		        ./dirtyc0w dirtycow_test EXPLOITABLE &>/dev/null

		        if grep -q EXPLOITABLE "dirtycow_test"
		        then
		            echo -e "\e[1;31m\tVulnerable to Dirty C0w\e[00m\n"
		        else
		           	echo -e "\e[1;32m\tNot vulnerable to Dirty C0w\e[00m\n"
		        fi

		        # Clean up
		        rm -rf dirtycow_test dirtyc0w dirtyc0w.c
		    fi
		fi
	}

footer()
	{
		date=`date`
		echo -e "\n\e[1;33mScan finished at: $date\e[00m\n"
		echo -e "\n"
	}

call_each()
	{
		header
		system_info
		user_info
		file_system
		conf
		exploit
		footer
	}


call_each
