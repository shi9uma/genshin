# init

1.   zsh：`curl -fLo ~/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/.zshrc`
2.   powershell：`curl -fLo $PROFILE https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/powershell_profile.ps1`
3.   ssh：`mkdir -p ~/.ssh; curl -fLo ~/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/script/05-initial/authorized_keys`
     1.   root：`chmod 700 -R $HOME/.ssh`
     2.   user：`chmod 700 -R $HOME/.ssh`
4.   vim
     1.   `sudo apt-get install -y vim fzf ripgrep`
     2.   `curl -fLo /tmp/unix_install_vim.sh https://raw.githubusercontent.com/shi9uma/vim/main/diy/unix_install_vim.sh && chmod +x /tmp/unix_install_vim.sh && /tmp/unix_install_vim.sh`