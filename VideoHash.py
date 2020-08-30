from Crypto.Hash.SHA256 import SHA256Hash
vid1 = '6.2.birthday.mp4_download'
vid2 = '6.1.intro.mp4_download'


# precondition: non-empty file
def hashVideo(vid_str):

    with open(vid_str, 'rb') as vid:
        blocks = []
        block = vid.read(1024)
        while block:
            blocks.append(block)
            block = vid.read(1024)
        print(len(blocks))

        hash = SHA256Hash(blocks[-1]).digest()
        for i in range(2, len(blocks)+1):
            hash = SHA256Hash(blocks[-i] + hash).digest()

        return hash.hex()

print(hashVideo(vid1))
print(hashVideo(vid2))