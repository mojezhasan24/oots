#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
java -cp "$DIR/smart-att.jar:$DIR/bluecove-2.1.1.jar:$DIR/bluecove-bluez-2.1.1.jar" SmartAttendanceSystemv2
