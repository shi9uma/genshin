# init

1.   zsh：`curl -fLo ~/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/.zshrc`
2.   powershell：`curl -fLo $PROFILE https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/powershell_profile.ps1`
3.   ssh：
     1.   `mkdir -p ~/.ssh && curl -fLo ~/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/authorized_keys && chmod 700 -R $HOME/.ssh`
     2.   `sudo curl -fLo /etc/ssh/sshd_config https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/sshd_config`
     3.   `systemctl start ssh && systemctl enable ssh`
4.   vim
     1.   `sudo apt-get install -y vim fzf ripgrep`
     2.   `curl -fLo /tmp/unix-install-vim.sh https://raw.githubusercontent.com/shi9uma/vim/main/diy/unix-install-vim.sh && chmod +x /tmp/unix-install-vim.sh && /tmp/unix-install-vim.sh`