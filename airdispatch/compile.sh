#!bin/sh
rm Message.pb.go && protoc Message.proto --go_out=. && go install airdispat.ch/airdispatch
