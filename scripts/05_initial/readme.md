# init

1.   zsh：`curl -fLo ~/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/.zshrc`
2.   powershell：`curl -fLo $PROFILE https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/powershell_profile.ps1`
3.   ssh：`curl -fLo ~/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/authorized_keys`
     1.   root：`chmod 700 /root/.ssh`，`chmod 600 /root/.ssh/authorized_keys`
     2.   user：`chmod 655 ~/.ssh`，`chmod 640 ~/.ssh/authorized_keys`
4.   vim
     1.   `sudo aptitude install vim fzf ripgrep`
     2.   `curl -fLo /tmp/unix_install_vim.sh https://raw.githubusercontent.com/shi9uma/vim/main/diy/unix_install_vim.sh && chmod +x /tmp/unix_install_vim.sh; /tmp/unix_install_vim.sh`