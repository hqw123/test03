/***********************************************************

  UC encrypt and decrypt functions, in fact a special case
  of Blowfish. 
  
***********************************************************/

#include <iostream>
#include "UCCrypt.h"

#define N 16

unsigned long P_BOX[N + 2] =
{
0xf76bc585UL,0x65962b81UL,0x18dca56fUL,0x4fac29d0UL,
0x9e9bac95UL,0x8db87348UL,0xaad9edc4UL,0x48c80c76UL,
0x1b9acc1cUL,0x052dbb63UL,0xb770d647UL,0xcb04ba2bUL,
0x761a7855UL,0x6c42dd7cUL,0x02e15fc0UL,0x28709d8bUL,
0xd8ef2f96UL,0x54ad213dUL 
};

unsigned long S_BOX[4][256] = {
{
0xe8829dc3UL,0xeb502774UL,0x8f573c02UL,0xbb60e580UL,
0xe14a9badUL,0xf1c29e2dUL,0x33835f6aUL,0x0a52a492UL,
0x887395a6UL,0x8f5341adUL,0xb733de32UL,0x96148951UL,
0x072b1fd7UL,0x8c1ad02fUL,0xc26ac84aUL,0x2f8f53f7UL,
0xaff270a3UL,0x82bd301dUL,0x1b60c1c0UL,0xe70858eeUL,
0xaa1ce907UL,0x0a1fbdc7UL,0x5dc31a6eUL,0x32bbedcbUL,
0xc0e36a3eUL,0xe574d2d7UL,0x56d3a613UL,0x3671cc54UL,
0xb6f9e4a5UL,0x167afb06UL,0xa2c62b0bUL,0xa373673eUL,
0x06f04873UL,0xb5065184UL,0x6b0e4aeaUL,0x0b92aec4UL,
0x849bd258UL,0x5cbb0205UL,0x97c0b247UL,0xfc3ee53eUL,
0xf73369fcUL,0xc8ed7c22UL,0x82ea1d3cUL,0x740aae44UL,
0x7f757ef2UL,0x15bf99e2UL,0x0f0a9592UL,0xfb4e4f24UL,
0x219e9016UL,0x47904756UL,0x4565ab9bUL,0xb8bbf24aUL,
0x0baf0958UL,0x86053738UL,0x8d9621afUL,0x9defd1b5UL,
0xd488da06UL,0x1f892839UL,0xa44e3201UL,0x056eb0a5UL,
0x1eb50112UL,0xb9839847UL,0x07dad8c0UL,0x0529373fUL,
0x7ea4f6b9UL,0xca6eeac0UL,0xebde0ed3UL,0x8f67f7cfUL,
0x4d9b1b95UL,0xdacf3de6UL,0x69f33dbbUL,0xe09b7153UL,
0x969b08b4UL,0xab1549ffUL,0xa36773f6UL,0xe50c17acUL,
0x0d7ba469UL,0x5964933bUL,0xf19c9135UL,0xcf841846UL,
0xed3a043bUL,0xfb033b94UL,0x9aefe276UL,0xbadfcd60UL,
0xfd600e45UL,0xe4995617UL,0x44098621UL,0xe813aaa6UL,
0xcc6c2614UL,0x3cccec49UL,0x834255d3UL,0x5c8c6c75UL,
0x7db874edUL,0x1b242520UL,0x1c38f026UL,0xdb13269dUL,
0x25a986f4UL,0x3ba82a22UL,0x5f7e57b5UL,0xc3c21c1eUL,
0x2d5bc0f3UL,0xb256fca9UL,0x8f288c87UL,0xac4e1f9eUL,
0x2d15fa4fUL,0xa452dc2cUL,0xbef60d28UL,0xd634b576UL,
0x11f7dd3bUL,0x9d052b9fUL,0x4bd88bf2UL,0x52526d5fUL,
0x817fdf1fUL,0x0cb1d3bbUL,0xd62fc88aUL,0xb417b41dUL,
0x30bdef29UL,0xb461f7f9UL,0x460f55ecUL,0xb2bef8d0UL,
0x0edb6ddeUL,0xb734b020UL,0xffc7cfc8UL,0x19839d8cUL,
0xbbd34961UL,0x6793e17bUL,0x43fdca33UL,0x241f9741UL,
0x6c42adeaUL,0x07362568UL,0x66e0e816UL,0x61814c62UL,
0x67052becUL,0xfa96d017UL,0xfdb8e024UL,0x4c1ad193UL,
0xacd61618UL,0xf3616915UL,0x49ff8f43UL,0x6c3b632fUL,
0x3638271aUL,0xe561ace9UL,0xc1860813UL,0xda6f207aUL,
0x9e63659fUL,0x3a0ceb65UL,0x67718450UL,0x9336ba5fUL,
0xc008e651UL,0xe88cd76bUL,0xa52cffcdUL,0xc3ab174aUL,
0x1d4f6f09UL,0x7cd32b49UL,0xf8fc8addUL,0x4e40eae8UL,
0xf2dcbd34UL,0xe30fcbabUL,0x77a2688cUL,0x8c7a5654UL,
0x29e08b46UL,0x5a0eb55eUL,0x35c6a32bUL,0x266c69f0UL,
0xf6c31893UL,0x9b16f67fUL,0x8b66f32eUL,0xb7a453bbUL,
0xebf3644dUL,0xa99d1adcUL,0xeff5ecb4UL,0x3f8bde39UL,
0xf507c63fUL,0xae760104UL,0xa66fe37cUL,0xd354071bUL,
0xc711feddUL,0x4d399e3eUL,0x236ab63bUL,0x5a2804a9UL,
0x0ec712fdUL,0xbcaca3acUL,0x8ddf6b95UL,0xc371632dUL,
0x58ed79b1UL,0x60b337cfUL,0x8f009cb8UL,0x89426c1bUL,
0xbb3a9c28UL,0x4e29b3aaUL,0x6f7482b4UL,0x0e26fc32UL,
0x1aef67d0UL,0x25987c7cUL,0xbe3e4c65UL,0x4fe69bfcUL,
0x4482c40dUL,0xd4fb7d11UL,0x8015a8c8UL,0xd8297638UL,
0x263cdf8aUL,0x39928d6aUL,0x0a3c4190UL,0x7af29274UL,
0x6b99d46bUL,0xc88c872aUL,0x67683defUL,0x21cc5f40UL,
0x258de74fUL,0x0ab81f15UL,0x25cdb7faUL,0xbc06f7a4UL,
0x117762e7UL,0x7c9bacd4UL,0x107c20e0UL,0x55a93764UL,
0xfff88e78UL,0x90a6aecfUL,0xc381dffcUL,0xf941ded0UL,
0x7dda6916UL,0x8a38cdccUL,0x1dfeb0adUL,0x1ca968ecUL,
0xdbdded31UL,0x85837fd1UL,0xc494c466UL,0x733494f7UL,
0x790c1e9bUL,0x3971db95UL,0xbdffdde3UL,0x63a515d5UL,
0xb7b583f8UL,0x99ce85aeUL,0xed6f4e7fUL,0xec0313a1UL,
0xf387b28aUL,0x7b8e4ff0UL,0x1206f0e9UL,0x96419f4fUL,
0x4619d924UL,0xbc4457d8UL,0x19f0458dUL,0x2f3cdf29UL,
0xd5dc53a8UL,0xf0aa801fUL,0x50998e4aUL,0x48acb94fUL,
0xd058307fUL,0xcd73cb76UL,0xc9d0dc6cUL,0x69e051c3UL,
0x3a320a2dUL,0x1fb4e601UL,0x63ed2405UL,0x61b8732aUL
},
{
0xba2e294bUL,0xc91eb2bfUL,0x96d402f9UL,0x34a15036UL,
0x8bd770acUL,0xb2c0fc38UL,0x24a8f002UL,0x13f1dc36UL,
0x89e37f74UL,0xeaebcdf1UL,0xdb41e120UL,0xb734c4bcUL,
0x239f15c8UL,0x467c873eUL,0x1a89f68fUL,0x6bbe8b36UL,
0xf44a57dcUL,0x44bbd1fdUL,0xdb70f0d9UL,0x78fffeb6UL,
0x870e3603UL,0x643d0331UL,0x440bc518UL,0x4a41267eUL,
0xcccbe9e6UL,0x848282c3UL,0x31ad7519UL,0x6913c9c7UL,
0xed940221UL,0xf6f2bd09UL,0x54fe5c6eUL,0x4da726ccUL,
0x342bf6d3UL,0x465af622UL,0x40ffc516UL,0x382d3a60UL,
0xf2b8dfb6UL,0x6ec65dcaUL,0xdeae4965UL,0x7fa48606UL,
0x04d23d8fUL,0x2f34980fUL,0xa9d9645fUL,0x29e98d81UL,
0x5d6e2e42UL,0xf3d350c0UL,0xdf63f7efUL,0xea5e055bUL,
0x98858257UL,0x3c0b419aUL,0x66f4d8ffUL,0x36c227ceUL,
0x36c0fe8aUL,0xc09117eaUL,0x1c4d1347UL,0x6e32c5aeUL,
0xf660a2a2UL,0x37d30058UL,0x17b55bbcUL,0xd889c5e2UL,
0x1a5fd94cUL,0xaec5309bUL,0x25cec82aUL,0xd7af7bd7UL,
0x95dafac1UL,0x01c6e872UL,0x65430857UL,0x9551feb3UL,
0xe5cfccb5UL,0x53957954UL,0x052a15c0UL,0x5f2bd478UL,
0x7ac60a81UL,0xaccf5510UL,0x89af5dbeUL,0xf705376fUL,
0x3c594f08UL,0x8548a4b0UL,0x1f234f1fUL,0x5391709dUL,
0x5e3d3fb4UL,0x47d729b0UL,0x7ec9812cUL,0xd5a6ae32UL,
0x7603424dUL,0x51a919f4UL,0x228c33dcUL,0x91552312UL,
0x32bd4299UL,0x8de3ca81UL,0x3822f923UL,0x6bfba8cfUL,
0x2279ed17UL,0xcce56705UL,0x0d1478d5UL,0xacf71adfUL,
0x1980b8bcUL,0x3a17c834UL,0x6420a927UL,0xa0e6613aUL,
0xae0a94cfUL,0x4396ba22UL,0xb6f14e88UL,0xf2878d16UL,
0x01eac631UL,0x83e0a0a0UL,0x30e8ad30UL,0x72306630UL,
0x794eff29UL,0xafd93a55UL,0xbbd400edUL,0xf1ac50c2UL,
0x64c2bebeUL,0xe13f0cf0UL,0x0fa04599UL,0x64e2c4a6UL,
0x2f575413UL,0x57e353ebUL,0x185f4720UL,0x31f04b68UL,
0xe38f029eUL,0x5335bdf5UL,0x2234c1d7UL,0x68016d2dUL,
0x3768aaf1UL,0x1ae979f5UL,0x9d235a36UL,0x49dd69d4UL,
0x24c998b0UL,0xd18f1d5eUL,0x8b15a122UL,0xfaaeae46UL,
0x7475435cUL,0x1c7a2bc0UL,0x56b753bbUL,0x13a67ad9UL,
0xac706d3cUL,0x9a0ebd84UL,0x0cd30ec9UL,0xe3436705UL,
0xd3efcd6aUL,0x81cd33b2UL,0x801dc7fbUL,0xaa3d97faUL,
0xb102b8dcUL,0x86d7132fUL,0xdddb3472UL,0xc7de1ae5UL,
0x240f7b98UL,0xa8fa2bc8UL,0x8db8d65aUL,0x1886d567UL,
0xce9e22f0UL,0x44b78fa8UL,0xc8852465UL,0xb5a865a6UL,
0x6f8d432eUL,0x86611500UL,0xa2b8a9ddUL,0x644e6079UL,
0x220843e1UL,0xed6d9c6eUL,0x723669ffUL,0xe79b0978UL,
0xc41a3c09UL,0x3a556a84UL,0xaab00a3eUL,0x30d59917UL,
0x73c30afdUL,0x57494d1aUL,0x7ca5e4aeUL,0x49d4d38bUL,
0xc959a13aUL,0x68fa2780UL,0xda1e2794UL,0x3cfeb458UL,
0xbb9ca747UL,0xcaae2d86UL,0x601439ecUL,0x04ff2689UL,
0x421d9eb1UL,0xd7ba81f5UL,0x6ffae92eUL,0xe0f0c3f1UL,
0x223145f6UL,0xfaf307d9UL,0xe82d16f8UL,0x2caac369UL,
0x74122053UL,0x8c6d4cd6UL,0x0e4f8491UL,0x6f720a2eUL,
0x04d705faUL,0xfacdf7b9UL,0xc15a2180UL,0x86f1bf01UL,
0xb9cc2fecUL,0x2a4c343bUL,0x76cd6490UL,0x7c7c17c2UL,
0xc5a013abUL,0xc481f769UL,0x58627b59UL,0xcbcec14aUL,
0x6e0d882cUL,0x7c14dfb7UL,0x45c34784UL,0x6c357e7dUL,
0x2ff096d8UL,0xf991bb0dUL,0xb5ff615cUL,0x508b7b04UL,
0x2d3f648cUL,0xaedf6a8dUL,0x957ecde5UL,0x0476c3a0UL,
0x0054cf21UL,0x106b010eUL,0x5cda8362UL,0xf0fcf126UL,
0xb0908235UL,0x5a71a25bUL,0xc52eedf3UL,0x17ad3a5eUL,
0x18669294UL,0x837b0998UL,0x2e637ed7UL,0xd7da1f93UL,
0x58b3dcdfUL,0xe3833720UL,0x54f8fe61UL,0xeadd8f13UL,
0x0280c0d1UL,0x51e865d4UL,0x6d01c480UL,0xbe1a3a45UL,
0x6a7fc478UL,0x489b96b3UL,0x30867029UL,0xac8f1f16UL,
0xb2378d7cUL,0xc5bbe6ecUL,0x5106ffb6UL,0x29261e41UL,
0x7a1e1e2bUL,0xdb6675edUL,0xcb0a69afUL,0x940acb7cUL,
0x8ebee854UL,0xe70311baUL,0xce80da09UL,0x6203de2eUL,
0x99e53b3fUL,0xb93297f1UL,0xd2191872UL,0xac4a4a0aUL
},
{
0x56389713UL,0x385f4d09UL,0x8dccfe2cUL,0x822dfd43UL,
0x2921f3a3UL,0x90152d38UL,0xbd9f8b4fUL,0x959745a8UL,
0x74c46f92UL,0x96a59fe1UL,0x95c5c6b3UL,0x5946e1ccUL,
0x7261d4e9UL,0x51cbc19dUL,0x7b798fa4UL,0xe1f61d1bUL,
0x2f54b9efUL,0xf87125deUL,0x9a9308b2UL,0xf2b3a2b3UL,
0x3a631beeUL,0xeafecbc4UL,0x8c848ddfUL,0x723c5d33UL,
0x0a535df1UL,0x521180bfUL,0xb89ffe4dUL,0x0969f219UL,
0x5b14224fUL,0xab299920UL,0x5da101e9UL,0x3f6608adUL,
0x94e2b510UL,0x453284c7UL,0xa95a5f3dUL,0xbdff1545UL,
0x1ba8389eUL,0x975f8949UL,0xa69a79fbUL,0xa953e6e8UL,
0xe35b1dfbUL,0xee686dccUL,0x22b17a8fUL,0xa99a5c95UL,
0x76bab148UL,0xcf8aa81fUL,0xb1e420b5UL,0x431a364fUL,
0x6dccb4afUL,0x56208d38UL,0x66a71fa3UL,0x0bf1f3acUL,
0xbcbae3b9UL,0xab893a63UL,0xae478d42UL,0x61a63cc9UL,
0x1aab0ea7UL,0xa394f8e3UL,0x2028ea13UL,0x1b5a3fadUL,
0x9dca8651UL,0x6f7650beUL,0x3da5c031UL,0x32353a28UL,
0x8c8b4889UL,0xf1d49473UL,0x5677ab3aUL,0xe5ef5812UL,
0xf144b51dUL,0x22db96d7UL,0xd585518cUL,0xbcd090deUL,
0x0c5f3dd3UL,0xa4e0443aUL,0x5f2d76e8UL,0x13c4cdccUL,
0xc6b7f554UL,0xfd49dd6dUL,0xc7a0a158UL,0x894163e8UL,
0x7742af84UL,0xfbcc9a29UL,0x3325780bUL,0xfe294040UL,
0x07116facUL,0x939643d5UL,0x7091c405UL,0x11bea5aaUL,
0xc398e1ccUL,0x73bfd779UL,0x1979332dUL,0xd638ff16UL,
0x81bdba61UL,0xdf20c6eaUL,0xf2d8f082UL,0x8e31892fUL,
0x2a412cb0UL,0x0f8f47efUL,0x20c3c4d9UL,0x64f9c181UL,
0xa3fcc84eUL,0x3e658f2aUL,0x71d6e85bUL,0x01186933UL,
0x55b8e4e7UL,0xabcc5e05UL,0x96600330UL,0x7a3edcd9UL,
0x1016d5b5UL,0x3c7d1268UL,0xd8adf6d8UL,0x4974e102UL,
0xce23e6bbUL,0xca1e16a7UL,0x48d423e3UL,0xb086f6aaUL,
0x86c49904UL,0xda6991f5UL,0x295731f4UL,0x004fc19eUL,
0x9c3e5c38UL,0x6f63b85bUL,0x42abf0fdUL,0x1949edc9UL,
0x42cf42ebUL,0x1e231a69UL,0x85ae20d5UL,0x9c1320f3UL,
0x1935299cUL,0x20d92fa9UL,0xbf661150UL,0xcfe38a9eUL,
0x94fa472eUL,0x950bcec6UL,0x8c5efe31UL,0x9a8a4aacUL,
0xcc971050UL,0x21fc18fdUL,0x335dac45UL,0x2af2cabaUL,
0x4693b1ecUL,0x062055d2UL,0x259db7e1UL,0x85a278cdUL,
0xdf9b07c8UL,0x89068416UL,0x0c076db6UL,0xb381ec71UL,
0xaca85c2dUL,0xec6da305UL,0xcdcef407UL,0xed7a47c6UL,
0x30a316d9UL,0xfd669b07UL,0x31daf9f1UL,0x9c35e196UL,
0x4cdf003dUL,0x79ef5bfeUL,0x2fa0086fUL,0x67cda7e4UL,
0x56e7d441UL,0x22bfbbc8UL,0xd5b48646UL,0x15320a2fUL,
0xbbd55fc4UL,0x8cfe0192UL,0x28c5e5e1UL,0x14fae4f2UL,
0xd99b34ebUL,0x2925d72eUL,0xd18c68d3UL,0x8405b365UL,
0xea7963cbUL,0x32263993UL,0xee543bb3UL,0xa315fe54UL,
0xe93b2455UL,0xa324ad6fUL,0xff8d3cccUL,0x1c1869dfUL,
0x51e1cfcdUL,0x90bd68e7UL,0x6404900eUL,0xeeadd02eUL,
0x1fb8f0c4UL,0xd95e7f43UL,0xc351c579UL,0x01ffb946UL,
0x6ee25e5fUL,0x4bd2d295UL,0xb32e6e23UL,0xce7caa2dUL,
0x882e2e77UL,0x0684f9b1UL,0x7b3d380dUL,0xa35bc4acUL,
0x4f82682cUL,0x82c152beUL,0xd16f634cUL,0xb20c047dUL,
0x49f5a2d3UL,0xee282801UL,0xe3ad0702UL,0xd8f024d4UL,
0x890de68bUL,0x611cc642UL,0xa613b5b2UL,0x78c8cfdfUL,
0x73c7a63eUL,0xd82d2d5aUL,0x42f958a1UL,0xf1c13c87UL,
0x0ca82c33UL,0x95372d1fUL,0x876f6325UL,0x0cd8ea0bUL,
0x6d7f041cUL,0x9a90c8f9UL,0x8cdd8522UL,0x07406dbdUL,
0x843291cfUL,0x9adefed2UL,0x6d7e1c62UL,0xaa2830a7UL,
0x41935929UL,0xe0854322UL,0x139d4c3aUL,0x7d0f5bafUL,
0x0cc531c0UL,0x81252c05UL,0x20126aa9UL,0x945319f0UL,
0x99c0beacUL,0x00812924UL,0x9fa07d96UL,0xa0703fbdUL,
0x26e71bb5UL,0x89593fcbUL,0xf0d462fcUL,0x5c15459bUL,
0x44015740UL,0xfe46d58eUL,0xf54832ebUL,0xabdfbac7UL,
0xaefc90d6UL,0x6de9c867UL,0x8459e57eUL,0x953dddd2UL,
0xb937f767UL,0x381df2f0UL,0x3bd3291eUL,0xb21f383aUL,
0x0fe9a180UL,0xee84c3e0UL,0x85e16202UL,0xe32ff120UL
},
{
0x1389e16dUL,0xb1f307d0UL,0x853b19a8UL,0x57c63dc4UL,
0xdc18d6f6UL,0xb52eeb7dUL,0x65953351UL,0xb5ee2e6fUL,
0x7165f589UL,0xa3c587b2UL,0xea17c538UL,0x3efe7f3fUL,
0x4d19c762UL,0xa60b0950UL,0x61e87fd2UL,0x3c03d1aeUL,
0xfd5f0540UL,0xfb3593c7UL,0xbce34264UL,0x62a536a1UL,
0xa47a2b15UL,0x2c13b603UL,0xaa20b677UL,0x5678e96dUL,
0x795c853fUL,0x44281864UL,0x86e6964eUL,0xc5851881UL,
0xf0b2e5a7UL,0x1d42e41dUL,0x90f525a8UL,0x970efcd4UL,
0x0cfce305UL,0x794cfc08UL,0x6740503dUL,0x44d619ebUL,
0x4b3dbe14UL,0x05e4b50bUL,0xb392e004UL,0xc6507e93UL,
0xcced1231UL,0xccbac5aeUL,0x4b4797f9UL,0x18b4e996UL,
0xa977ba49UL,0x1b383eb4UL,0xf42978baUL,0x95dce866UL,
0xba802872UL,0x19aa45b7UL,0xfd7e13eeUL,0x84260eb4UL,
0x7e3d7278UL,0xd7efcc1aUL,0xc2b18b8cUL,0x12f2ae30UL,
0x82bf9053UL,0x20555f6dUL,0x9620197dUL,0x9ef63f3cUL,
0x611109eeUL,0x5c8e0fe4UL,0xbf7e8f38UL,0x9a5c2a96UL,
0x4aa6a03bUL,0xdbb94994UL,0xc5b6052bUL,0xc51a1203UL,
0x756e1a17UL,0xf62646b2UL,0x706db75cUL,0x21de4e28UL,
0x571239c5UL,0x2aea5ef4UL,0xc7b44030UL,0xc59ad4adUL,
0x76d22617UL,0x31286a66UL,0x0625ed8fUL,0x5c91c804UL,
0x5949d2c0UL,0x85a36e8aUL,0x7a277fafUL,0x29a9ea5aUL,
0x7d5127f7UL,0xb29d9d49UL,0xd72ca919UL,0x9a990e94UL,
0x7d947a12UL,0x9fd72bbaUL,0x983fe8e0UL,0xe72e5f6aUL,
0x6dcf6bbeUL,0xc1ea15efUL,0xc9ad54bfUL,0x7ea68c78UL,
0x22cf8c7eUL,0x9019e1dcUL,0x36fe83edUL,0xed4cb9b5UL,
0xdb612a60UL,0x637b6dd0UL,0x63bfd2fdUL,0x74427124UL,
0xf93a9026UL,0xd4f2bc6bUL,0x6690cb6fUL,0x86ed7bb0UL,
0xfa3c442cUL,0xd9e5daf6UL,0xe34ee30fUL,0xea7173f2UL,
0x08eb0f06UL,0xb9decf4aUL,0x79dc1d0bUL,0x63e47d4eUL,
0x58e5ae4dUL,0x239a97f4UL,0xeeffaca6UL,0xa522d10cUL,
0xe992a730UL,0xf3308760UL,0x9c67053dUL,0x769743d8UL,
0xfece03f4UL,0x93a77b3eUL,0xc3d5c6eeUL,0x56317212UL,
0x153a16e7UL,0x241bac37UL,0x807a2992UL,0xab387d94UL,
0xb62bb4c5UL,0x6649f4d4UL,0xcfbc5007UL,0x196fdf3eUL,
0xbd2d2284UL,0x4c0e009dUL,0xfde6803fUL,0x6ab11173UL,
0xb9453859UL,0x4e2f6421UL,0x20b2f6ffUL,0xac9880c4UL,
0x06208a64UL,0x4e7c07d1UL,0xd1a9cc12UL,0xbf2254ffUL,
0x0e6d902dUL,0x49ca752aUL,0x6c030ed6UL,0xb7b406b2UL,
0x39099801UL,0x260adc24UL,0x0752601aUL,0x2af7e865UL,
0xb2984fa0UL,0xe8b7148fUL,0x77364590UL,0x7a432987UL,
0x490c907aUL,0x37352909UL,0x2fa261e3UL,0x7c9db3e2UL,
0x57d546a8UL,0xc1df0689UL,0x5954abc6UL,0x95e5133cUL,
0x933f0467UL,0xb3fdc716UL,0xd44c4100UL,0x75be8d54UL,
0x301fa11fUL,0x3beade20UL,0x833b6257UL,0xe32dde8fUL,
0x645782daUL,0xe02ae01cUL,0xabd1a947UL,0xd389d370UL,
0xa96a2a7bUL,0x367a3cb3UL,0xcc9393e0UL,0xfa6a3e97UL,
0x7ca85382UL,0x8c898917UL,0xbce53cf2UL,0x6447f06cUL,
0x1935fb0dUL,0x8b0bd7e9UL,0x69f04a72UL,0x9afad0dbUL,
0x5124be9fUL,0x0fbfba2bUL,0x37758dbeUL,0xac9db953UL,
0x611cf4cbUL,0x9740782fUL,0x96763002UL,0x217d681cUL,
0x6cc8d6bcUL,0xc3110831UL,0x9bd83236UL,0x2f89de7eUL,
0x52c37dc2UL,0xc3024c10UL,0x78d10219UL,0xb310ec3bUL,
0x9b17712dUL,0xc7cf612bUL,0x79b8af76UL,0x0497db29UL,
0x931876b3UL,0x48419e79UL,0x6e391d5cUL,0x580e182dUL,
0x846e3d20UL,0x14b49a48UL,0x1f306857UL,0x4ea98899UL,
0x2ef66cadUL,0x5f98deaaUL,0xf27c8c07UL,0x5121a164UL,
0x4318177fUL,0x7a2f9303UL,0x6eb513aaUL,0x74ce0f63UL,
0x2626d863UL,0xb3370775UL,0x5180cb98UL,0xa9a27da5UL,
0xd32910b6UL,0xba6ba8b4UL,0xa65e44ddUL,0x56e88fa7UL,
0xa2f04c1fUL,0x1e6cffe9UL,0x6788bf08UL,0x4f31ac2bUL,
0x6a7509b7UL,0xceac192eUL,0xf27ea781UL,0xd71f51e4UL,
0xfddaa59aUL,0xa559e3e6UL,0xc74903b6UL,0xca2f5adcUL,
0x612fdb14UL,0x0adda67dUL,0xd64c82f3UL,0xfa74751aUL,
0x369d36b8UL,0xe55be19fUL,0xb396703cUL,0x070aafcaUL
}};

u_long UCCrypt::BlowFish(u_long x)
{
   u_short a;
   u_short b;
   u_short c;
   u_short d;
   u_long  y;

   d = x & 0x00FF;
   x >>= 8;
   c = x & 0x00FF;
   x >>= 8;
   b = x & 0x00FF;
   x >>= 8;
   a = x & 0x00FF;
   y = S_BOX[0][a] + S_BOX[1][b];
   y = y ^ S_BOX[2][c];
   y = y + S_BOX[3][d];

   return y;
}

void UCCrypt::Encipher(u_long *xl, u_long *xr)
{
   u_long  Xl;
   u_long  Xr;
   u_long  temp;
   short   i;

   Xl = *xl & 0xffffffff;
   Xr = *xr & 0xffffffff;

   for (i = 0; i < N; ++i) {
      Xl = Xl ^ P_BOX[i];
      Xr = BlowFish(Xl) ^ Xr;

      temp = Xl;
      Xl = Xr;
      Xr = temp;
   }

   temp = Xl;
   Xl = Xr;
   Xr = temp;

   Xr = Xr ^ P_BOX[N];
   Xl = Xl ^ P_BOX[N + 1];
  
   *xl = Xl;
   *xr = Xr;
}

void UCCrypt::Decipher(u_long *xl, u_long *xr)
{
   u_long  Xl;
   u_long  Xr;
   u_long  temp;
   short   i;

   Xl = *xl & 0xffffffff;
   Xr = *xr & 0xffffffff;

   for (i = N + 1; i > 1; --i) {
      Xl = Xl ^ P_BOX[i];
      Xr = BlowFish(Xl) ^ Xr;

      /* Exchange Xl and Xr */
      temp = Xl;
      Xl = Xr;
      Xr = temp;
   }

   /* Exchange Xl and Xr */
   temp = Xl;
   Xl = Xr;
   Xr = temp;

   Xr = Xr ^ P_BOX[1];
   Xl = Xl ^ P_BOX[0];

   *xl = Xl;
   *xr = Xr;
}

