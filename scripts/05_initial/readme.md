# init

1.   zsh：`curl -fLo ~/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/.zshrc`
2.   powershell：`curl -fLo $PROFILE https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/powershell_profile.ps1`
3.   ssh：`curl -fLo ~/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/authorized_keys`
     1.   root：`chmod 700 /root/.ssh`，`chmod 600 /root/.ssh/authorized_keys`
     2.   user：`chmod 655 ~/.ssh`，`chmod 640 ~/.ssh/authorized_keys`
4.   vim
     1.   配色：
          1.   `curl -fLo ~/.vim/colors/gruvbox.vim https://raw.githubusercontent.com/morhetz/gruvbox/master/autoload/gruvbox.vim`
          2.   `curl -fLo ~/.vim/autoload/gruvbox.vim https://raw.githubusercontent.com/morhetz/gruvbox/master/autoload/gruvbox.vim`
          3.   `curl -fLo ~/.vim/autoload/airline/themes/gruvbox.vim https://raw.githubusercontent.com/morhetz/gruvbox/master/autoload/airline/themes/gruvbox.vim`
          4.   `curl -fLo ~/.vim/autoload/lightline/colorscheme/gruvbox.vim https://raw.githubusercontent.com/morhetz/gruvbox/master/autoload/lightline/colorscheme/gruvbox.vim`
     2.   `curl -fLo ~/.vimrc https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/unix_vimrc`