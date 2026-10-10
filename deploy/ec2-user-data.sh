#!/bin/bash
# À coller dans "Advanced details > User data" au lancement de l'instance EC2 (Amazon Linux 2023).
# Installe Docker et Git, puis clone le repo. Le .env (secrets) est ajouté à la main ensuite.
dnf install -y docker git
systemctl enable --now docker
usermod -aG docker ec2-user
cd /home/ec2-user
sudo -u ec2-user git clone https://github.com/Monka31/Hackathon_Essec_Team_CFF.git vibeaudit || true
