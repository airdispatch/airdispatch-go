echo "Moving the Files into the Correct Go Package..."
mkdir $CI_HOME/src/airdispat.ch
mv $CI_HOME/src/github.com/huntaub/airdispatch-protocol/* $CI_HOME/src/airdispat.ch/
cd $CI_HOME/src/airdispat.ch/
echo "Installing Dependencies..."
go get code.google.com/p/goprotobuf/proto
go get code.google.com/p/go.crypto/ripemd160
# go get github.com/hoisie/web
echo "Installing Airdispatch..."
go install airdispat.ch/airdispatch
go install airdispat.ch/common
echo "Testing has Finished!"
