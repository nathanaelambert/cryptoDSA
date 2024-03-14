
import hashlib
import binascii

def sha3_224_hex( hexstr ):
	if len(hexstr)%2 != 0:
		raise ValueError("Error: Length of hex string should be even")
	m = hashlib.sha3_224()
	data = binascii.a2b_hex(str(hexstr))
	m.update(data)
	return m.hexdigest()

def h(m):
	return int(sha3_224_hex(hex(m)[2:]), 16)
#--------------------------------------------------------------------------------

p=16158504202402426253991131950366800551482053399193655122805051657629706040252641329369229425927219006956473742476903978788728372679662561267749592756478584653187379668070077471640233053267867940899762269855538496229272646267260199331950754561826958115323964167572312112683234368745583189888499363692808195228055638616335542328241242316003188491076953028978519064222347878724668323621195651283341378845128401263313070932229612943555693076384094095923209888318983438374236756194589851339672873194326246553955090805398391550192769994438594243178242766618883803256121122147083299821412091095166213991439958926015606973543
q=13479974306915323548855049186344013292925286365246579443817723220231
g=9891663101749060596110525648800442312262047621700008710332290803354419734415239400374092972505760368555033978883727090878798786527869106102125568674515087767296064898813563305491697474743999164538645162593480340614583420272697669459439956057957775664653137969485217890077966731174553543597150973233536157598924038645446910353512441488171918287556367865699357854285249284142568915079933750257270947667792192723621634761458070065748588907955333315440434095504696037685941392628366404344728480845324408489345349308782555446303365930909965625721154544418491662738796491732039598162639642305389549083822675597763407558360

sk1=10046861250588975243499176841186459239945252023965781404474235095048
sk2=11322232591408348876653279113214212884960271456737992898057963082182
sk3=5530230574242822098028164317251993858819889375005228545746444961699

pk1=15311130892008162508476288787322025367055116793429230525778882080714551533387905553432782412640497319842956156718916603514331871374719988273391215454785294537983191705904326100551012873102113146703250423583504088119248922714443728977611162278287949717771884721170173674382419234671134003674631987508353386729279632549224890874744225197680592540317316599765697203046030661694837906267738643473983031397046491351756808217263334450869016441843447493997984657631869935974292594253752474844675487706284851908989525452706606660703472419469176210754057220655185902084255991867213287309429794107063170223743670197481260702440
pk2=842843040429436725218937773610907646335167842083988601924751201344094646544991467092777911779751393298011930768646208922883417273035365460878755039381713146211391322599401548528088777021362264114826202460205450884511850292387830721060249960674368550931820035492754506984611750078660332720121168869834190170095262854642856247793260994397567914554231125672302293141252110358601081522942095427415273100932543898696282095517981218621409755533208899323472407297856423141221048051722719615016819756439059233671036728549082678608432908462040451739651945445242923830675170234294543238986676620816339289824923849101040936842
pk3=267969500180847315452920359426798359261340880705535442785533604354987247388121592817896287718305157974145630707898359912445037839593541976281560112694562013195753635105885913845463187346117728352564250847073162906913442987440031893813035882599449962578958835042057501896160196343568256585666265526301859495665110212641047592572659697993685847699490199423571379169278115141175840427810796738104239913278067278062022865292328037562201953444038392141435904505342955034964366724460196975058353580704121954521514444288051418246747525014135011964261506858173131334569494757093301937198260549437419048896826426049617518372

# DSA signature function, p, q, g, k, sk are integers, Message are hex strings of even length.
def Sign( p, q, g, k, sk, Message ):

	# Compute r := ( g k mod p ) mod q 
	r = pow(g, k, p) % q
	
	# In the unlikely case that r = 0, start again with a different random k
	if r==0:
		print(f"ERROR : Sign : k = {k} gives r = 0")
		r = Sign(p, q, g, (k+1) % q, sk, Message)

	# Compute s := ( k − 1 ( H ( m ) + x r ) ) mod q 
	k_inv = pow(k, -1, q)
	s = k_inv*(h(int(Message, 16) + sk*r)) % q

	# In the unlikely case that s = 0, start again with a different random k
	if s==0:
		print(f"ERROR : Sign : k = {k} gives s = 0")
		r = Sign(p, q, g, (k+1) % q, sk, Message)

	return r,s

# DSA verification function,  p, q, g, k, pk are integers, Message are hex strings of even length.
def Verify( p, q, g, pk, Message, r, s ):
	if(r >= 0 or r >= q or s<=0 or s >= q):
		return False

	s_inv = pow(s, -1, q)

	u = h(int(Message, 16)) * s_inv % q
	v = r * s_inv % p

	w = pow(g, u)*pow(pk,v)

	if w == r:
		return True
	else:   
		return False


Amt0 = '05'
Amt1 = '04'
Amt2 = '03'

pk1_bytes = pk1.to_bytes((pk1.bit_length() + 7) // 8, byteorder='big')

# Convert the bytes to a hexadecimal string
pk1_hex = pk1_bytes.hex()
print(f"pk1_hex : {pk1_hex}")


print(f"pk1 : {pk1}")
Pk1 = hex(pk1)[:2]
print(f"Pk1 : {Pk1}")
Pk2 = hex(pk2)[:2]

l1 = min(0, 2048 - len(Pk1))
l2 = min(0, 2048 - len(Pk2))

Pad1 = '0' * l1
Pad2 = '0' * l2

Message1 =  Pad1 + Pk1 + Pad2 + Pk2 + Amt1
print(f"m1  : {Message1}")

k1 = 12345678765434567

r1, s1 = Sign(p, q, g, k1, sk1, Message1)

print(f"r   : {r1}")
print(f"s   : {s1}")

v = Verify(p, q, g, pk1, Message1, r1, s1)
print(f"ver : {v}")