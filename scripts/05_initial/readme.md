# init

1.   zsh：`curl -o ~/.zshrc https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/.zshrc`
2.   powershell：`curl -o $PROFILE https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/powershell_profile.ps1`
3.   ssh：`curl -o ~/.ssh/authorized_keys https://raw.githubusercontent.com/shi9uma/genshin/main/scripts/05_initial/authorized_keys`
     1.   root：`chmod 700 /root/.ssh`，`chmod 600 /root/.ssh/authorized_keys`
     2.   user：`chmod 655 ~/.ssh`，`chmod 640 ~/.ssh/authorized_keys`