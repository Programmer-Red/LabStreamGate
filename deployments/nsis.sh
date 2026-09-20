#!/usr/bin/env bash

echo "Windows deployment script for LabStreamGate"

export APP_NAME="LabStreamGate"

if [ ${PWD##*/} != $APP_NAME ]; then
  echo "This script MUST be run from the $APP_NAME/ directory"
  exit 1
fi

echo '---- Running make install'
mkdir -p dist
APP_ROOT=dist
cp ./target/release/labstreamgate.exe "${APP_ROOT}/labstreamgate.exe"
cp ./target/release/labstreamgate-desktop.exe "${APP_ROOT}/labstreamgate-desktop.exe"
curl -fsSL https://aka.ms/vs/17/release/vc_redist.x64.exe -o "${APP_ROOT}/vc_redist.x64.exe"

mv $APP_ROOT $APP_NAME

echo '---- Compressing package'
7z a $APP_NAME-portable-windows-msvc-x86_64.zip $APP_NAME

echo '---- Creating installer'
mv $APP_NAME windows/$APP_NAME
cp windows/$APP_NAME.ico windows/$APP_NAME/$APP_NAME.ico
pushd windows >/dev/null
makensis setup.nsi
popd >/dev/null
mv windows/labstreamgate-desktop-installer-windows-msvc-x86_64.exe $APP_NAME-installer-windows-msvc-x86_64.exe
