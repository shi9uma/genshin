# init

1.   zsh：`curl -fLo ~/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05-initial/.zshrc`
2.   powershell：`curl -fLo $PROFILE https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05-initial/powershell_profile.ps1`
3.   ssh：`curl -fLo ~/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05-initial/authorized_keys`
     1.   root：`chmod 700 /root/.ssh`，`chmod 700 /root/.ssh/authorized_keys`
     2.   user：`chmod 700 ~/.ssh`，`chmod 700 ~/.ssh/authorized_keys`
4.   vim
     1.   `sudo apt-get install -y vim fzf ripgrep`
     2.   `curl -fLo /tmp/unix_install_vim.sh https://raw.githubusercontent.com/shi9uma/vim/main/diy/unix_install_vim.sh && chmod +x /tmp/unix_install_vim.sh && /tmp/unix_install_vim.sh`