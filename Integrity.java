import com.sun.xml.internal.ws.api.client.SelectOptimalEncodingFeature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.e.TypeECurveGenerator;

import java.math.BigInteger;

/*
    Checking only when it is necessary: Enabling integrity auditing based
    on the keyword with sensitive information privacy for encrypted cloud data
 */
public class Integrity {

    public static void main(String[] args){
        int rBits = 160;
        int qBits = 512;

        PairingParametersGenerator pg = new TypeECurveGenerator(rBits, qBits);
        Pairing pairing = PairingFactory.getPairing("params.properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        /*
            1. System initialization
               q order, G1, G2 are already set in the params.properties file.
               e: G1 * G1 -> G2   This pairing function is also already set in the param.properties file
               Two generators u, g are selected here from the elliptic curve group G1
               Three secure hash functions - yet to be decided
               Symmetric encryption algorithm - to use the existing code from the Internet
               Pseudorandom keys - yet to be decided
               secret key x chosen from Zq* here
               public key y = g power x computed here
        */
        Element u = pairing.getG1().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = g.powZn(x);
        System.out.println("u is : " + u);
        System.out.println("g is : " + g);
        System.out.println("x is : " + x);
        System.out.println("y is : " + y);

        /* Setup phase - starts here */

        /* Step 1: For each file, the user splits the file into s blocks.
                   and encrypts them by the symmetric key algorithm (e.g. AES) */
        // Let us assume our file has 3 blocks such as b1, b2, b3. Let us randomly select the block values of the file from zq*
        Element b1 = pairing.getZr().newRandomElement().getImmutable();
        Element b2 = pairing.getZr().newRandomElement().getImmutable();
        Element b3 = pairing.getZr().newRandomElement().getImmutable();

        // The blocks b1, b2, b3 are encrypted using AES algorithm.\
        // Let us assume that, the encrypted blocks for b1, b2, b3 are c1, c2, c3.
        // For now, let us randomly select the values of c1, c2, c3.

        Element c1 = pairing.getZr().newRandomElement().getImmutable();
        Element c2 = pairing.getZr().newRandomElement().getImmutable();
        Element c3 = pairing.getZr().newRandomElement().getImmutable();

        /* Step 2: The user extracts all the keywords, then builds the keyword set W.
        Let us assume that, we have three keywords. It is represented using an array. */
        Element k0 = pairing.getZr().newRandomElement().getImmutable();
        Element k1 = pairing.getZr().newRandomElement().getImmutable();
        Element k2 = pairing.getZr().newRandomElement().getImmutable();
        Element keyword[] = new Element[3];
        keyword[0] = k0;
        keyword[1] = k1;
        keyword[2] = k2;

        /* Step 3 :
            For each keyword wk, the user creates an n-bit binary string as the index vector vwk.
            He initializes every element this index vector to 0.
            For each file Fi, if it contains keyword wk, then the user sets the i-th bit of the index vector to 1: vwk[i] = 1

            In this case, we assume that, indexvector[3].
            Indexvector[0] = 1 means, keyword[0] is present in file 1.
            Indexvector[1] = 1 means, keyword[1] is present in file 1.
            Indexvector[2] = 1 means, keyword[2] is present in file 1.
         */
        Element indexvector[] = new Element[3];
        indexvector[0] = pairing.getZr().newElement(new BigInteger("1"));
        // indexvector[0] is vw0
        indexvector[1] = pairing.getZr().newElement(new BigInteger("1"));
        // indexvector[1] is vw1
        indexvector[2] = pairing.getZr().newElement(new BigInteger("1"));
        // indexvector[2] is vw2

        /* Setup phase - ends here */

        /* Index generation - starts here */
        System.out.println("\n\n Index Generation");
        // step 1: For each keyword wk, the user computes pi(wk) as
        //         the address of each row in the secure index.
        System.out.println("Step 1:");
        Element pik0 = pairing.getZr().newRandomElement().getImmutable();
        /* In future, if the code correctly works as per the research manuscript,
           this pik0 should be replaced by pik0 = pi(k0)
           LLLrly for pik1, pik2 also.
         */
        Element pik1 = pairing.getZr().newRandomElement().getImmutable();
        Element pik2 = pairing.getZr().newRandomElement().getImmutable();

        // step 2: For each keyword wk, the index vector is encrypted using
        //         the exclusive or of vwk and f(pi(wk)).
        //         In future, fpik0 will be replaced with a suitable pseudo-random function.
        System.out.println("Step 2:");
        Element fpik0 = pairing.getZr().newRandomElement().getImmutable();
        Element fpik1 = pairing.getZr().newRandomElement().getImmutable();
        Element fpik2 = pairing.getZr().newRandomElement().getImmutable();

        Element evpiwk0 = pairing.getZr().newElement(new BigInteger(element_xor(indexvector[0].toString(), fpik0.toString())));
        System.out.println("evpiwk0 is : " + evpiwk0);
        Element evpiwk1 = pairing.getZr().newElement(new BigInteger(element_xor(indexvector[1].toString(), fpik1.toString())));
        Element evpiwk2 = pairing.getZr().newElement(new BigInteger(element_xor(indexvector[2].toString(), fpik2.toString())));

        // String string_indexvector0 = indexvector[0].toString();
        // v1 = pairing.getZr().newElement(new BigInteger(""));


        //int_indexvector[0] = indexvector[0].toBigInteger();

        /* int a = 7;
        int b = 4;
        int c = a ^ b;
        System.out.println("c is : " + c);
        */

        /* step 3 : For each keyword wk, the user creates an empty set swk=0.
        For each i belongs to [1,n], if vwk[i] = 1, the user adds this file index i to the set swk.

        In our code, since we have assumed that we have only one file, swk0 =1, swk1 = 1, swk2 = 1.
        This means that certainly, all the three keywords k0, k1, k2 are present in the file F1 whose identity is 1.
        * */
        System.out.println("Step 3:");
        Element swk0 = pairing.getZr().newElement(new BigInteger("1"));
        Element swk1 = pairing.getZr().newElement(new BigInteger("1"));
        Element swk2 = pairing.getZr().newElement(new BigInteger("1"));

        /* Step 4: For each keyword wk, the user computes the RAL
            For each keyword wk, the user computes the RAL (Relation Authentication Label),
            ohm(pi(wk)) = {ohm(wk,1), ohm(wk,2), ..., ohm(wk,s)}
            Here, s refers to the numbers of blocks in a each file.
            where, ohm(wk,1) = product of(H1(IDi||j)-1 ). H3(j). H2(pi(wk)||j)
            In our project, we have assumed that, we have only 1 file.
            we have three keywords in our project. k0, k1, k2.
            k0 is present in file 1.
            Similarly, k1, k2 are also in file 1.
            In our project, we don't have more than one file, Hence,
            all the keywords are present in this file 1.
        */
        // Element ohm_wk1 = (product of(H1(ID1||1) inverse). H3(1). H2(pi(wk)||1)) power x
        // Let us assume that,
        // ohm_block1_v1 = product of(H1(ID1||1) inverse)
        // ohm_block1_v2 =  H3(1)
        // ohm_block1_v3 =  H2(pi(wk)||1)
        // Therefore, Element ohm_wk1 = ohm_block1_v1.ohm_block1_v2.ohm_block1_v3
        // Thus, since we have three keywords in our project, we have three values such as to compute
        // ohm_wk1, ohm_wk2, ohm_wk3
        System.out.println("Step 4:");
        Element ohm_block1_v1 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_block1_v2 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_block1_v3 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_wk1 = ((ohm_block1_v1.add(ohm_block1_v2)).add(ohm_block1_v3)).powZn(x);

        Element ohm_block2_v1 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_block2_v2 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_block2_v3 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_wk2 = ((ohm_block2_v1.add(ohm_block2_v2)).add(ohm_block2_v3)).powZn(x);

        Element ohm_block3_v1 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_block3_v2 = pairing.getG1().newRandomElement().getImmutable();
        Element ohm_block3_v3 = pairing.getG1().newRandomElement().getImmutable();

        Element ohm_wk3 = ((ohm_block3_v1.add(ohm_block3_v2)).add(ohm_block3_v3)).powZn(x);

        System.out.println("ohm_wk1 is " + ohm_wk1);
        System.out.println("ohm_wk2 is " + ohm_wk2);
        System.out.println("ohm_wk3 is " + ohm_wk3);

        /* step 5 */
           // The user sets I = {pi(wk), evpiwk, ohm(pi(wk)} for each k=1,2,...,m
        /* Index gen - ends here */

        /* Authentication Generation - starts here */

            /* For each encrypted block cij, the user computes the authenticator
               sigma_ij = [H1(IDi||j).u power cij] power x

               where, i = file no from 1 to n, j = block number from 1 to s

               In our project,
               we have only one file with identity 1, and 3 blocks.
               Let us assume m1, m2, m3 represent the block values (which are integers).
               Let us assume c1, c2, c3 represent the enctypted block values (which are integers).

               Moreover, we have to compute the authenticators for only 3 blocks.
               sigma_file1_block1, sigma_file1_block2, sigma_file1_block3
            */
            Element sigma_file1_block1 = ((ohm_block1_v1.invert()).add(u.powZn(c1))).powZn(x);
            Element sigma_file1_block2 = ((ohm_block1_v2.invert()).add(u.powZn(c2))).powZn(x);
            Element sigma_file1_block3 = ((ohm_block1_v3.invert()).add(u.powZn(c3))).powZn(x);
        /* Authentication Generation - ends here */

        /* trapdoor generation - starts here */
            /*
                The user computes the search trapdoor Tw' = { pi(w'), f(pi(w')) }
                The trapdoor means, the data owner, i.e. the file owner whose is the owner of the file 1 in our case,
                wants to search the file 1 using the keyword k0.
                So, to securely send the keyword k0, he sends pik0, fpik0 to the TPA.
                Apart from this, no value is computed in this module.

                For trapdoor purpose, we call Tw as Tw_dash
                T_w1_dash = {pik0, fpik0}
             */
            System.out.println("\n \n Trapdoor generation for the keywords to be searched.");
            System.out.println("Let us assume that, we want search the blocks containing the keyword k0");
            System.out.println("pik0 is : " + pik0);
            System.out.println("fpik0 is : " + fpik0);
        /* trapdoor generation - ends here */

        /* Challenge generation - By TPA - starts here */
            System.out.println("\n Challenge Generation: ");
            /*
                Step 1: The TPA randomly chooses a c-elements subset Q from [1 to s]

                In our project, we have s = 3. This means, we have only three blocks 1, 2, 3.
                Let us assume that, we want to check the block no.1, block no. 2 only for verification.
                Hence, our c-element subset has only block no.1, block no.2
                i.e. c = {1,2}
             */

            /*
                Step 2: For each j in Q, the TPA randomly chooses vj from Zq*
                In our case, j = 1, 2.
                Therefore, the TPA selects, v1, v2 from Zq*
             */
            Element v1 = pairing.getZr().newRandomElement().getImmutable();
            Element v2 = pairing.getZr().newRandomElement().getImmutable();
            System.out.println("v1 is : " + v1);
            System.out.println("v2 is : " + v2);
            /* step 3: Now, the TPA sends the auditing challenge Chal = {Tw', {j, vj} j in Q} to the Cloud Server.
                       In our case, Chal = {Tw0, {(1,v1), (2, v2)}}
             */
        /* Challenge generation - ends here */

        /* Proof Generation: By Cloud Server (CS)
            1. The CS parses the challenge Chal = {Tw0, {(1,v1), (2, v2)}}
            2. For the keyword pi(w) = pi(w'), the cloud find teh the corresponding
               encrypted row evpiwk and the RAL ohm_piwki from the secure index.
               The cloud decrypts the corresponding encrypted index vector
               vwk = evpiwk0 xor f(piwk)
        * */
            System.out.println("\n \n Proof generation:");
            Element vw0 = pairing.getZr().newElement(new BigInteger(element_xor(evpiwk0.toString(), fpik0.toString())));
            System.out.println("vw0 is : " + vw0);

        /* 3. The cloud initiates an empty set swk = phi. i.e. swk = {empty set}
              For each i in [1,n], if vwk[i] == 1, then the cloud add i to swk.

              In our case, we have i = 1 only. Here, i refers to the file no.
              Since, in our project, we have only one file, i =1 only.
              In our case, vwk[1] = 1. This is because, this keyword k0 is in the file 1.
              Therefore, we have to set swk0 = 1
        * *
         */
        Element swk0_cs = pairing.getZr().newElement(new BigInteger("1"));
        // This is same as setting swk0 in 3rd module, step c.

        /* * Step 4: The cloud computes T = sigma_ij power vj for i in swk, j in Q
                     In our project, we assume that, k0 is present in blocks m1, m2.
                     Therefore, the authenticators sigma_file1_block1, sigma_file1_block2 for the encrypted blocks c1, c2 are taken by the CS.

         */
        // Element T = ((sigma_file1_block1.powZn(v1)).add(ohm_wk1.powZn(v1))).add((sigma_file1_block2.powZn(v2)).add(ohm_wk1.powZn(v2)));
        Element T = ((sigma_file1_block1.powZn(v1)).add(sigma_file1_block2.powZn(v2))).add((ohm_wk1.powZn(v1)).add(ohm_wk2.powZn(v2)));
        Element meu = (c1.mul(v1)).add(c2.mul(v2));
        System.out.println("\n Proof Generation: ");
        System.out.println("T is : " + T);
        System.out.println("meu is : " + meu);

        /*
            Now, the cloud server CS sets the auditing response
            Proof = {T, meu}
            That is, the CS sends this Proof to the TPA for verification.
         */

    /* Proof generation - ends here */

    /* Proof verification - starts here */
        /* The TPA checks the validity of the following equation:
        *  e(T,g) = e( for j=1 in Q ((H3(j).H2(piw'||j ) power vj)).u power meu, y )
        *
        * In our project,
        * e(T,g) = e( ((H3(1).H2(piw')||1) power v1 + (H3(1).H2(piw')||2) power v2).u power meu, y)
        * Here, L.H.S. = e(T,g)
        *       R.H.S. = e( ((H3(1).H2(piw')||1) power v1 + (H3(1).H2(piw')||2) power v2).u power meu, y)
         */
        Element LHS = pairing.pairing(T,g);
        System.out.println("LHS is :" + LHS);

        Element RHS = pairing.pairing((((ohm_block1_v2.add( ohm_block1_v3)).powZn(v1)).add((ohm_block2_v2.add( ohm_block2_v3)).powZn(v2))).add(u.powZn(meu)),y);
        System.out.println("RHS is :" + RHS);

    /* Proof verification - ends here */

        /* Only for rough use */
        Element p1 = pairing.getG1().newRandomElement().getImmutable();
        Element p2 = p1.invert().getImmutable();
        System.out.println("\n \n For Rough use only : ");

        System.out.println("p1 is : " + p1);
        System.out.println("p2 is : " + p2);
        Element p3 = p1.sub(p2);
        System.out.println("p3 is : " + p3);
        /* Only for rough use */
     }
    public static String element_xor(String v1, String v2){
        System.out.println("v1 is : " + v1);
        System.out.println("v2 is : " + v2);
        StringBuffer v3 = new StringBuffer();
        for (int i=0;i<v1.length();i++){
            v3.append(v1.charAt(i) ^ v2.charAt(i));
        }
        System.out.println("v3 is : " + v3);
        return v3.toString();
    }

    // Just to check

}



