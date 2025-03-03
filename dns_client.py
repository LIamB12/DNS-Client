import socket

# helper function, parses a resource record from the dns response
# takes the starting byte of the name field and the entire DNS response as input
# returns starting byte of next record
def parse_and_print_resource_record(record_start, response):

    name, end_of_name = parse_name(record_start, response)
    record_type = int.from_bytes(response[end_of_name:end_of_name+2], "big")
    record_class = int.from_bytes(response[end_of_name + 2:end_of_name+4], "big")
    record_ttl = int.from_bytes(response[end_of_name + 4:end_of_name+8], "big")
    rdlength = int.from_bytes(response[end_of_name + 8:end_of_name+10], "big")
    record_data_start = end_of_name + 10
    record_data = response[end_of_name + 10:end_of_name+ 10 + rdlength]

    print("------------------------------------")
    print("    Name:", name)

    # 'A' record
    if record_type == 1:
        print("    Record type: 'A'")
        
        # accumulate each ip address octet into a . separated string
        ip_parts = [str(byte) for byte in record_data]
        ip_address = ".".join(ip_parts)

        print("    Resolved IP:", ip_address)

    # 'CNAME' record
    elif record_type == 5:
        print("    Record type: 'CNAME'")
        cname, _ = parse_name(record_data_start, response)
        print("    Canonical Name:", cname)

    # 'SOA' record
    elif record_type == 6:
        print("    Record type: 'SOA'")
        mname, mname_end = parse_name(record_data_start, response)

        rname, rname_end = parse_name(mname_end, response)

        serial = int.from_bytes(response[rname_end:rname_end + 4], "big")
        refresh = int.from_bytes(response[rname_end + 4:rname_end + 8], "big")
        retry = int.from_bytes(response[rname_end + 8:rname_end + 12], "big")
        expire = int.from_bytes(response[rname_end + 12:rname_end + 16], "big")
        minimum = int.from_bytes(response[rname_end + 16:rname_end + 20], "big")

        print("    mname:", mname)
        print("    rname:", rname)
        print("    serial:", serial)
        print("    refresh:", refresh)
        print("    retry:", retry)
        print("    expire:", expire)
        print("    minimum:", minimum)

    # There are a lot more record types. I am assuming the 3 above are enough for this IP resolution assignment
    else:
        print("    Record Type Number:", record_type)
        print("    Parsing for this record type not yet implemented")

    next_record_start = end_of_name + 10 + rdlength
    return next_record_start



# helper function, parses name fields from the dns response accounting for compression with pointers
# takes the starting byte of the name field and the entire DNS response as input
def parse_name(current_byte, response):

    # accumulator for labels
    labels = []

    followed_pointer = False

    # stores byte number the name ends at
    end_of_name = current_byte + 1

    while True:

        # read length byte
        length = response[current_byte]

        # check for terminator
        if length == 0:

            # if no pointers followed, name field ends one byte after the terminator
            if not followed_pointer:
                end_of_name = current_byte + 1
            break

        # length byte is a pointer if it starts with 11, check using bit mask
        if (length & 0b11000000) == 0b11000000:

            # if this is our first pointer, name field ends 2 bytes after it, since pointer uses 2 bytes
            if not followed_pointer:
                end_of_name = current_byte + 2

            followed_pointer = True

            # find which byte to jump to by reading the 14 bytes following the "11" pointer marker
            # we remove the marker with a bit mask, shift 8 bits, and apply 'or' to combine the two bytes 
            jump_to_byte = ((length & 0b00111111) << 8) | response[current_byte + 1]

            # we then jump to the specified byte in the response and continue reading
            current_byte = jump_to_byte
            continue

        # if length byte is not a pointer, read the next {length} bytes as an ascii label and store it
        else:
            labels.append(response[current_byte + 1:current_byte + 1 + length].decode("ascii"))
            current_byte += 1 + length

    return ".".join(labels), end_of_name

# main function
def resolve_hostname():

    # collect user input for hostname
    hostname = input("Enter hostname: ")

    # use google's public dns server
    dns_server = "8.8.8.8"
    port = 53

    print("")
    print("Server:", dns_server)
    print("Address:", dns_server + "#" + str(port))

    # set transaction ID to a random 16 bit number
    ID = 0b0000000010101010

    # set our QR, OPCODE, AA, TC, RA, Z, RCODE to 0, and RD to 1 for a type A recursive query
    FLAGS = 0b_0_0000_0_0_1_0_000_0000

    # one question
    QDCOUNT = 0b0000000000000001

    # no answers yet
    ANCOUNT = 0b0000000000000000

    # no NS RRs
    NSCOUNT = 0b0000000000000000

    # no additional RRs
    ARCOUNT = 0b0000000000000000

    # pack header info into a single bytestring
    header = ID.to_bytes(2, "big") + FLAGS.to_bytes(2, "big") + QDCOUNT.to_bytes(2, "big") + ANCOUNT.to_bytes(2, "big") + NSCOUNT.to_bytes(2, "big") + ARCOUNT.to_bytes(2, "big")

    # convert hostname into proper (length + string) format
    labels = hostname.split(".")
    QNAME = b""
    for label in labels:
        QNAME += len(label).to_bytes(1, "big")
        QNAME += label.encode()

    # add null terminator byte
    QNAME += b"\x00"

    # set QTYPE and QCLASS to 1
    QTYPE = 0b0000000000000001
    QCLASS = 0b0000000000000001

    # create question record
    question = QNAME + QTYPE.to_bytes(2, "big") + QCLASS.to_bytes(2, "big")

    # combine header and question record
    request = header + question

    # create UDP socket to send the query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    # send request to the dns server
    sock.sendto(request, (dns_server, port))
   
    # await response and close socket
    response, addr = sock.recvfrom(512)
    sock.close()

    # response format:
    # header:
    #   ID (2 bytes)
    #   FLAGS (2 bytes)
    #   QDCOUNT (2 bytes)
    #   ANCOUNT (2 bytes)
    #   NSCOUNT (2 bytes)
    #   ARCOUNT (2 bytes)
    # question:
    #   QNAME (variable bytes, parsing required)
    #   QTYPE (2 bytes)
    #   QCLASS (2 bytes)
    # resource records:
    #   NAME (variable bytes, parsing required)
    #   TYPE (2 bytes)
    #   CLASS (2 bytes)
    #   TTL (2 bytes)
    #   RDLENGTH (2 bytes)
    #   RDATA (RDLENGTH bytes)

    # header is first 12 bytes
    header = response[:12]

    # read header info
    id = int.from_bytes(header[:2], byteorder="big")

    # I am assuming handling response truncation is not neccessary for this assignment
    flags = header[2:4]
    qdcount = int.from_bytes(header[4:6], byteorder="big")
    ancount = int.from_bytes(header[6:8], byteorder="big")
    nscount = int.from_bytes(header[8:10], byteorder="big")
    arcount = int.from_bytes(header[10:12], byteorder="big")

    print("")
    print("Answer Count:", ancount)
    print("Authoritative Record Count:", nscount)
    print("Additional Record Count:", arcount)
    print("")

    # Question record starts at byte 12
    # parse QNAME
    qname, end_of_qname = parse_name(12, response)

    # print question data
    print("QUESTION:")
    print("   ", "Name:", qname)
    print("   ", "Type:", "A")
    print("   ", "Class:", "IN")
    print("")

    # first resource record starts 4 bytes after the end of QNAME
    record_start = end_of_qname + 4

    # loop through each answer record
    print("ANSWERS:")
    for _ in range(ancount):
        record_start = parse_and_print_resource_record(record_start, response)
    print("")

    # loop through each authoritative record
    print("AUTHORITATIVE RECORDS:")
    for _ in range(nscount):
        record_start = parse_and_print_resource_record(record_start, response)
    print("")

    # loop through each additional record
    print("ADDITIONAL RECORDS:")
    for _ in range(arcount):
        record_start = parse_and_print_resource_record(record_start, response)
    print("")


resolve_hostname()
