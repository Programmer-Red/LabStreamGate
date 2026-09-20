#!/bin/bash

set -ex

APP="target/release/bundle/osx/LabStreamGate.app"
APP_NAME="LabStreamGate"
BIN="$APP/Contents/MacOS/labstreamgate-desktop"
ZIP="./LabStreamGate.app.zip"

cd crates/desktop && cargo bundle --release

cd ../..

ls -alh $APP
# codesign --timestamp --verify -vvv --deep --options=runtime --sign $IDENT $APP
zip -r $ZIP $APP
# xcrun notarytool submit --apple-id $USERNAME --team-id $IDENT --password $PASSWORD --wait $ZIP
# xcrun stapler staple $APP
hdiutil create $APP_NAME-tmp.dmg -ov -volname $APP_NAME -fs HFS+ -srcfolder $APP
hdiutil convert $APP_NAME-tmp.dmg -format UDZO -o $APP_NAME.dmg
