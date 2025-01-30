GIT_FABRIC_DIR=temp_fabric

git clone https://github.com/danielmiessler/fabric $GIT_FABRIC_DIR

rm -rf prompts/fabric_patterns/*

rm -rf $GIT_FABRIC_DIR/patterns/raycast

cp -r $GIT_FABRIC_DIR/patterns/* prompts/fabric_patterns/

rm -rf $GIT_FABRIC_DIR