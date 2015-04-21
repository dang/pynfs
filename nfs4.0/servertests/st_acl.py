from testmod import FailureException
from nfs4_const import *
from environment import check, checklist
from nfs4_type import nfsace4, createtype4, nfstime4, settime4
from nfs4state import NFS4Error
from nfs4lib import list2bitmap
import pprint

class MyPrettyPrinter(pprint.PrettyPrinter):
    def format(self, object, context, maxlevels, level):
        if isinstance(object, int):
            return hex(object), True, False
        else:
            return pprint.PrettyPrinter.format(self, object, context, maxlevels, level)

pp = MyPrettyPrinter(indent=2)

MODE4_ALL = MODE4_RUSR | MODE4_WUSR | MODE4_XUSR | MODE4_RGRP | MODE4_WGRP | MODE4_XGRP | MODE4_ROTH | MODE4_WOTH | MODE4_XOTH

MODE4_DEF = MODE4_RUSR | MODE4_WUSR | MODE4_XUSR | MODE4_RGRP | MODE4_XGRP | MODE4_ROTH | MODE4_XOTH

# assuming server will accept any small positive integer as an owner
# name.  In particular, these tests probably won't work over krb5,
# when string names are expected.

def setacl(c, fh, acl):
    """Set an ACL on a file

    If a file handle is not available, a path can be used instead

    Returns results of setattr
    """
    #pp.pprint(fh)
    ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: acl})]
    return c.compound(ops)

def create_file(c, name, acl=None, attrs={FATTR4_MODE: MODE4_DEF}):
    """ Create a file

    Optionally set an ACL on the file.
    File is closed after return
    """
    fh, stateid = c.create_confirm(name, attrs=attrs)
    res = c.close_file(name, fh, stateid)
    if acl != None:
        check(res)
        res = setacl(c, fh, acl)
    return res


def testACL(t, env):
    """SETATTR/GETATTR of a simple ACL

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL1
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    ops = c.use_obj(fh)
    acl = [nfsace4(0, 0, 0,"123")]
    ops += [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res)
    ops = c.use_obj(fh)
    ops += [c.getattr([FATTR4_ACL])]
    res = c.compound(ops)
    check(res)

def testLargeACL(t, env):
    """SETATTR/GETATTR of a large ACL

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL2
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    ops = c.use_obj(fh)
    acl = []
    # using larger id's just to try for a larger reply:
    for i in range(20):
        acl += [nfsace4(0, 0, 0, "%d" % (i + 10000))]
    ops += [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res)
    ops = c.use_obj(fh)
    ops += [c.getattr([FATTR4_ACL])]
    res = c.compound(ops)
    check(res)

def testACLPrecedence(t, env):
    """ALLOW and DENY types have precedence
    over future unALLOWED bits depending on
    which was first

    FLAGS: acl all
    DEPEND: LOOKFILE RD1
    CODE: ACL3
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@'),
            nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@')]
    #creates a file, closes it, sets acl, returns compound result
    res = create_file(c, t.code, acl)
    check(res, msg="Setting Read Allow before Read Deny on %s" % t.code)
    fh, stateid = c.open_confirm(t.code, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="Close from successful read on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@'),
            nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@')]

    res = setacl(c, fh, acl)
    check(res, msg="Setting Read Deny before Read Allow on %s" % t.code)
    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_READ,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_ACCESS, msg="Open for failed read on %s" % t.code)

ACE4_ACCESS_FOO_ACE_TYPE = 0x000000FFL
def testACLSupport(t,env):
    """Makes sure the server has NFS4
    ACLSUPPORT and that the server
    rejects a request it cannot store

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL4
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    ops = c.use_obj(fh)
    acl_attr = c.do_getattr(FATTR4_ACLSUPPORT, fh)
    if(acl_attr == 0):
        #COMEBACK when I get a chance, debug testmod
        #and try to make the other test work too
        #msg = "NFS4 ACLS are not supported on this server"
        #raise FailureException(msg)
        raise NFS4Error(NFS4ERR_OP_ILLEGAL)
    acl = [nfsace4(ACE4_ACCESS_FOO_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@')]
    ops += [c.setattr({FATTR4_ACL: acl}, stateid)]
    res = c.compound(ops)
    check(res, NFS4ERR_ATTRNOTSUPP)

#List directory
#write data
#add file

def testACLRead(t, env):
    """Test ACE4_READ_DATA access for OPEN
    READ checked for in ACL precedence test

    FLAGS: acl all
    DEPEND: RD1 MKFILE
    CODE: ACL5
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@')]
    res = create_file(c, t.code, acl)
    check(res, msg="Setting Read Deny on %s" % t.code)

    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_READ,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_ACCESS, msg="Open for read on %s" % t.code)

def testACLListDir(t, env):
    """Test ACE4_LIST_DIR access for READDIR

    FLAGS: acl all
    DEPEND: RDDR1
    CODE: ACL6
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.code])
    ops = c.use_obj(c.homedir + [t.code])
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@')]
    ops += [c.setattr({FATTR4_ACL: acl}), c.readdir_op(0, '', 4096, 4096, list2bitmap([]))]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Readdir deny on %s" % t.code)

    ops = c.use_obj(c.homedir + [t.code])
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@')]
    ops += [c.setattr({FATTR4_ACL: acl}), c.readdir_op(0, '', 4096, 4096, list2bitmap([]))]
    res = c.compound(ops)
    check(res, msg="Readdir allow on %s" % t.code)

def testACLWrite(t, env):
    """Test ACE4_WRITE_DATA access for OPEN
    and WRITE

    FLAGS: acl all
    DEPEND: WRT1
    CODE: ACL7
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_APPEND_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'EVERYONE@')]
    res = create_file(c, t.code, acl)
    check(res, msg="Setting Write Deny on %s" % t.code)
    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_ACCESS, msg="Open for denied write on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_APPEND_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Setting Write Allow on %s" % t.code)

    fh, stateid = c.open_confirm(t.code, access=OPEN4_SHARE_ACCESS_WRITE)
    ops = c.use_obj(fh)
    ops += [c.write_op(stateid, 0, FILE_SYNC4, 'write file')]
    res = c.compound(ops)
    check(res, msg="Write allow on %s" % t.code)

def testACLAddFile(t, env):
    """Test ACE_ADD_FILE access for OPEN
    and CREATE excluding NF4DIR

    FLAGS: acl all
    DEPEND: MKLINK
    CODE: ACL8
    """
    c = env.c1
    c.init_connection()

    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny add file on %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4LNK)
    check(res, NFS4ERR_ACCESS, msg="Create deny on %s/foo" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set allow add file on %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4LNK)
    check(res, msg="Create allow on %s/foo" % t.code)

def testACLAddSubdirectory(t, env):
    """Test ACE_ADD_SUBDIRECTORY
     on CREATE for NF4DIR

    FLAGS: acl all
    DEPEND: MKDIR
    CODE: ACL9
    """
    c = env.c1
    c.init_connection()

    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny add directory on %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, NFS4ERR_ACCESS, msg="Create deny on %s/foo" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set allow add directory on %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="Create allow on %s/foo" % t.code)

def testACLAppendData(t, env):
    """Test ACE_APPEND_DATA with a
    WRITE at EOF and ACE4_WRITE_DATA
    denied

    FLAGS: acl-append
    DEPEND:
    CODE: ACL10
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code, deny=OPEN4_SHARE_DENY_NONE)
    ops = c.use_obj(fh)
    ops += [c.write_op(stateid, 0, FILE_SYNC4, 'write file')]
    res = c.compound(ops)
    check(res, msg="Initial write on %s" % t.code)
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="Close from successful write on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_APPEND_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set [allow append] and [deny write] on %s" % t.code)

    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_WRITE,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="Open write on %s" % t.code)
    fh, stateid = c.confirm(t.code, res)

    ops = c.use_obj(fh)
    ops += [c.write_op(stateid, 11, FILE_SYNC4, 'write file again')]
    res = c.compound(ops)
    check(res, msg="Append on %s" % t.code)

    ops = c.use_obj(fh)
    ops += [c.write_op(stateid, 11, FILE_SYNC4, 'write file again')]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Rewrite on %s" % t.code)

def testACLReadAttrs(t, env):
    """Test ACE_READ_ATTRIBUTES by
    doing a getattr for file system
    attributes

    FLAGS: acl all
    DEPEND:
    CODE: ACL11
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_ATTRIBUTES, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c1, t.code, acl)
    check(res, msg="Setting Read-attr deny on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code])
    ops += [c2.getattr([FATTR4_SIZE])] #is this a valid attribute to checkout?
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Getattr deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_ATTRIBUTES, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Setting Read-attr allow on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code])
    ops += [c2.getattr([FATTR4_SIZE])]
    res = c2.compound(ops)
    check(res, msg="Getattr allow on %s" % t.code)

def testACLWtiteAttrs(t, env):
    """Test ACE_WRITE_ATTRIBUTES by
    doing a setattr for times associated with
    a file or directory.

    FLAGS: acl all
    DEPEND:
    CODE: ACL12
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_ATTRIBUTES, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c1, t.code, acl)
    check(res, msg="Setting Write-attr deny on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code])
    time = nfstime4(seconds=500000000, nseconds=0)
    settime = settime4(set_it=SET_TO_CLIENT_TIME4, time=time)
    ops += [c2.setattr({FATTR4_TIME_ACCESS_SET : settime,
                        FATTR4_TIME_MODIFY_SET : settime})]
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Setattr deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_ATTRIBUTES, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Setting Read-attr allow on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code])
    ops += [c2.setattr({FATTR4_TIME_ACCESS_SET : settime,
                        FATTR4_TIME_MODIFY_SET : settime})]
    res = c2.compound(ops)
    check(res, msg="Setattr allow on %s" % t.code)

def testACLDelete(t, env):
    """Test ACE_DELETE by
    deleting a file

    FLAGS: acl all
    DEPEND: RM1d
    CODE: ACL13
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    res = c1.create_obj(t.code, attrs={FATTR4_MODE:0777})
    check(res, msg="Create dir %s" % t.code)
    res = c1.create_file("foo", path=c1.homedir + [t.code] + ["foo"],
                         attrs={FATTR4_MODE: MODE4_ALL})
    check(res, msg="Create file %s/foo" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code] + ["foo"], acl)
    check(res, msg="Set deny delete file on %s/foo" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Delete deny on %s/foo" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code] + ["foo"], acl)
    check(res, msg="Set allow delete file on %s/foo" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, msg="Delete allow on %s/foo" % t.code)

def testACLReadACL(t, env):
    """Test ACE_READ_ACL by
    doing a getattr for acls

    FLAGS: acl all
    DEPEND:
    CODE: ACL14
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_ACL, 'EVERYONE@')]
    res = create_file(c1, t.code, acl)
    check(res, msg="Set deny read ACL on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.getattr([FATTR4_ACL])]
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Read ACL deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_ACL, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set allow read ACL on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.getattr([FATTR4_ACL])]
    res = c2.compound(ops)
    check(res, msg="Read ACL allow on %s" % t.code)

def testACLWriteACL(t, env):
    """Test ACE_WRITE_ACL by
    doing a setattr for acls
    and mode

    FLAGS: acl all
    DEPEND:
    CODE: ACL15
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_ACL, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c1, t.code, acl)
    check(res, msg="Set deny write ACL on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.setattr({FATTR4_MODE : MODE4_DEF})]
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Write ACL deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_ACL, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set allow write ACL on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.setattr({FATTR4_MODE : MODE4_DEF})]
    res = c2.compound(ops)
    check(res, msg="Write ACL allow on %s" % t.code)

def testACLWriteOwner(t, env):
    """Test ACE_WRITE_OWNER by
    doing a setattr for owner and
    owner_group

    FLAGS: acl all
    DEPEND:
    CODE: ACL16
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_OWNER, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c, t.code, acl)
    check(res, msg="Set deny write owner on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code])
    ops += [c.setattr({FATTR4_OWNER_GROUP : "nobody@nowhere",
                       FATTR4_OWNER : "nobody@nowhere"})]
    res = c.compound(ops)
    check(res, NFS4ERR_PERM, msg="Write owner deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_OWNER, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set allow write owner on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code])
    ops += [c.setattr({FATTR4_OWNER_GROUP : "nobody@nowhere",
                       FATTR4_OWNER : "nobody@nowhere"})]
    res = c.compound(ops)
    check(res, msg="Write owner allow on %s" % t.code)

def testACLReadNamedAttrs(t, env):
    """Test ACE_READ_NAMED_ATTRS
    by doing an OPENATTR when create_dir
    is false, and when a named attr dir
    already exists

    FLAGS: acl-namedattr
    DEPEND:
    CODE: ACL17
    """
    c = env.c1
    c.init_connection()
    res = create_file(c, t.code, None)

    #create_dir is true so it creates an named attr director
    #but a named attribute doesn't already exist
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(True)]
    res = c.compound(ops)
    check(res, msg="Open(create) new attrdir none on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_NAMED_ATTRS, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set read named attrs deny on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(False)]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Read named attrs deny on %s" % t.code)

    #create dir is true but an attribute dir already exists
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(True)]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Open(create) existing attrdir allow on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_NAMED_ATTRS, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set read named attrs allow on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(False)]
    res = c.compound(ops)
    check(res, msg="Read named attrs allow on %s" % t.code)

    #create dir is true but an attribute dir already exists
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(True)]
    res = c.compound(ops)
    check(res, msg="Open(create) existing attrdir allow on %s" % t.code)

def testACLWriteNamedAttrs(t, env):
    """Test ACE_WRITE_NAMED_ATTRS
    by doing an OPENATTR when create_dir
    is false, and when a named attr dir
    already exists

    FLAGS: acl-namedattr
    DEPEND:
    CODE: ACL18
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_NAMED_ATTRS, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_NAMED_ATTRS, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c, t.code, acl)
    check(res, msg="Set write named attrs deny on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(True)]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Write named attrs deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_NAMED_ATTRS, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_NAMED_ATTRS, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set write named attrs allow on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.openattr_op(True)]
    res = c.compound(ops)
    check(res, msg="Write named attrs allow on %s" % t.code)

def testACLDeleteChild(t, env):
    """Test ACE_DELETE_CHILD
    delete a file or directory
    within a directory

    FLAGS: acl all
    DEPEND:
    CODE: ACL19
    """
    c = env.c1
    c.init_connection()
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny delete child on %s" % t.code)
    res = c.create_file("foo", path=c.homedir + [t.code] + ["foo"])
    check(res, msg="Create %s/foo" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Remove deny on %s/foo" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set allow delete child on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Remove allow on %s/foo" % t.code)

def testACLExecute(t, env):
    """Test ACE_EXECUTE by
    looking up a file

    FLAGS: acl all
    DEPEND:
    CODE: ACL20
    """
    c = env.c1
    c.init_connection()
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny execute on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.lookup_op("foo")]
    res = c.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Execute deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set allow execute on %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code]) + [c.lookup_op("foo")]
    res = c.compound(ops)
    check(res, NFS4ERR_NOENT, msg="Execute allow on %s" % t.code)

def testACLGenericRead(t, env):
    """Test ACE_GENERIC_READ ace
    bitmask to make sure the system
    reads it

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL21
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_GENERIC_READ, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c, t.code, acl)
    check(res, msg="Setting generic-read deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_GENERIC_READ, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Setting generic-read allow on %s" % t.code)

def testACLGenericWrite(t, env):
    """Test ACE_GENERIC_WRITE ace
    bitmask to make sure the system
    reads
    it

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL22
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_GENERIC_WRITE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = create_file(c, t.code, acl)
    check(res, msg="Setting generic-write deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_GENERIC_WRITE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Setting generic-write deny on %s" % t.code)

def testACLDeleteBehavior(t, env):
    """Test deleting algorithm
    specified in the RFC additional
    ACL notes in section 12 without sticky bit

    FLAGS: acl all
    DEPEND:
    CODE: ACL23
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    c1.maketree([t.code, "foo"])
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set deny execute on %s" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.remove_op("foo")]
    res = c1.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Execute deny on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_GENERIC_WRITE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set allow generic write on %s" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.remove_op("foo")]
    res = c1.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Execute unspecified on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set allow execute on %s" % t.code)
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code] + ["foo"], acl)
    check(res, msg="Set allow delete on %s/foo" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.remove_op("foo")]
    res = c1.compound(ops)
    check(res, msg="Delete allow on %s/foo" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set allow delete child on %s" % t.code)
    res = c1.create_file("foo", path=c1.homedir + [t.code] + ["foo"])
    check(res, msg="Second create of %s/foo" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code] + ["foo"], acl)
    check(res, msg="Set deny delete on %s/foo" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.remove_op("foo")]
    res = c1.compound(ops)
    check(res, msg="Delete child allow on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set deny delete child on %s" % t.code)
    res = c1.create_file("foo", path=c1.homedir + [t.code] + ["foo"])
    check(res, msg="Third create of %s/foo" % t.code)
    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code] + ["foo"], acl)
    check(res, msg="Set deny delete on %s/foo" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.remove_op("foo")]
    res = c1.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Delete child deny on %s" % t.code)

    #final else
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Clear allow add file on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="Default case")

    # Allow cleanup
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE_CHILD, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Cleanup %s" % t.code)

def testACLDeleteBehaviorSticky(t, env):
    """Test deleting algorithm
    specified in the RFC additional
    ACL notes in section 12 sticky bit

    FLAGS: acl-svtx
    DEPEND: ACL23
    CODE: ACL23SVTX
    """
    c1 = env.c1
    c1.init_connection()
    c2 = env.c2
    c2.init_connection()
    c1.maketree([t.code, "foo"])
    #MODE4_SVTX set and principal owns parent dir
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code], acl)
    check(res, msg="Set allow add file on %s" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code])
    ops += [c1.setattr({FATTR4_MODE: MODE4_SVTX | MODE4_ALL})]
    res = c1.compound(ops)
    check(res, msg="Set SVTX on %s" % t.code)
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.remove_op("foo")]
    res = c1.compound(ops)
    check(res, msg="SVTX own parent on %s" % t.code)

    #MODE4_SVTX set and principal owns target but not parent dir
    res = c2.create_file("foo", path=c2.homedir + [t.code] + ["foo"])
    check(res, msg="Fourth create of %s/foo" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, msg="SVTX own target on %s/foo" % t.code)

    #MODE4_SVTX set and ACE4_WRITE_DATA is allowed by the target
    res = c1.create_file("foo", path=c1.homedir + [t.code] + ["foo"])
    check(res, msg="Fifth create of %s/foo" % t.code)
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'EVERYONE@')]
    res = setacl(c1, c1.homedir + [t.code] + ["foo"], acl)
    check(res, msg="Set allow write data on %s/foo" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, msg="SVTX write data on %s/foo" % t.code)

    #MODE4_SVTX set but nothing else is
    res = c1.create_file("foo", path=c1.homedir + [t.code] + ["foo"])
    check(res, msg="Sixth create of %s/foo" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, NFS4ERR_ACCESS, msg="SVTX only on %s" % t.code)

    #MODE4_SVTX not set, but allow ADD_FILE
    ops = c1.use_obj(c1.homedir + [t.code]) + [c1.setattr({FATTR4_MODE: MODE4_ALL})]
    res = c1.compound(ops)
    check(res, msg="Clear SVTX on %s" % t.code)
    ops = c2.use_obj(c2.homedir + [t.code]) + [c2.remove_op("foo")]
    res = c2.compound(ops)
    check(res, msg="Allow add file only on %s" % t.code)

def testACLAddfilePrecedence(t, env):
    """Test ACE_ADD_FILE does not
    imply ACE_ADD_SUBDIRECTORY

    FLAGS: acl all
    DEPEND:
    CODE: ACL24
    """
    c = env.c1
    c.init_connection()

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set allow add file %s" % t.code)
    res = c.create_file("foo", path=c.homedir + [t.code] + ["foo"])
    check(res, msg="Create file %s/foo" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["bar"], type=NF4DIR)
    check(res, NFS4ERR_ACCESS, msg="Create dir %s/bar" % t.code)

def testACLFlagFileInherit(t, env):
    """Test ACE4_FILE_INHERIT_ACE
    flag on a directory and file
    created in it

    FLAGS: acl all
    DEPEND:
    CODE: ACL25
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_FILE_INHERIT_ACE, ACE4_DELETE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit delete %s" % t.code)
    res = c.create_file("foo", path=c.homedir + [t.code] + ["foo"])
    check(res, msg="Create file %s/foo" % t.code)
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    if cacl[0] != acl[0]:
        raise FailureException("ACL not Inherited")
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Delete file %s/foo" % t.code)

def testACLFlagDirInherit(t, env):
    """Test ACE4_DIRECTORY_INHERIT_ACE
    flag on a directory and file
    created in it

    FLAGS: acl all
    DEPEND:
    CODE: ACL26
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE, ACE4_DELETE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit delete %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="create test dir %s/foo" % t.code)
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    inherited_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                             ACE4_INHERIT_ONLY_ACE, ACE4_DELETE, 'EVERYONE@'),
                     nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    if cacl != inherited_acl:
        raise FailureException("ACL not Inherited")
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Delete dir %s/foo" % t.code)

def testACLFlagInheritOnly(t, env):
    """Test ACE4_INHERIT_ONLY_ACE
    flag on a directory and a sub
    dir

    FLAGS: acl all
    DEPEND:
    CODE: ACL27
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                   ACE4_INHERIT_ONLY_ACE, ACE4_DELETE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit delete %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="create test dir %s/foo" % t.code)
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])

    inherited_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                             ACE4_INHERIT_ONLY_ACE, ACE4_DELETE, 'EVERYONE@'),
                     nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    if (inherited_acl != cacl):
        raise FailureException("ACL not Inherited")
        print("Exception!")
        #throw exception
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Delete dir %s/foo" % t.code)

def testACLFlagNoPropagateInherit(t, env):
    """Test ACE4_NO_PROPOGATE_INHERIT_ACE
    flag on a directory in a sub dir
    and a file in a sub dir

    FLAGS: acl all
    DEPEND:
    CODE: ACL28
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                   ACE4_NO_PROPAGATE_INHERIT_ACE, ACE4_DELETE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set no-propagate inherit delete %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="create test dir %s/foo" % t.code)
    inherited_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    if (inherited_acl != cacl):
        raise FailureException("ACL not Inherited")
        print("Exception!")
        #throw exception
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Delete dir %s/foo" % t.code)

    res = c.create_file("foo", path=c.homedir + [t.code] + ["foo"])
    check(res, msg="Create file %s/foo" % t.code)
    inherited_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    if (inherited_acl != cacl):
        raise FailureException("ACL not Inherited")
        print("Exception!")
        #throw exception
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Delete dir %s/foo" % t.code)

#how would I do this on pynfs?
def testACLFlagIdentifierGroup(t, env):
    """Test ACE4_IDENTIFIER_GROUP
    flag on a directory a sub dir
    and a file in a sub dir

    FLAGS: acl all
    DEPEND:
    CODE: ACL29
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                   ACE4_NO_PROPAGATE_INHERIT_ACE | ACE4_IDENTIFIER_GROUP,
                   ACE4_DELETE, '%d' % env.opts.gid),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_FILE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set identifier-group delete %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="create test dir %s/foo" % t.code)

    inherited_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                             ACE4_DELETE, '%d' % env.opts.gid)]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    if (inherited_acl != cacl):
        raise FailureException("ACL not Inherited")
        print("Exception!")
        #throw exception
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code])
    if (acl != cacl):
        raise FailureException("ACL not Inherited")
        print("Exception!")
        #throw exception
    ops = c.use_obj(c.homedir + [t.code]) + [c.remove_op("foo")]
    res = c.compound(ops)
    check(res, msg="Delete dir %s/foo" % t.code)

    ops = c.go_home() + [c.remove_op(t.code)]
    res = c.compound(ops)
    check(res)

def testACLAllowMode(t, env):
    """Test mode bits being set
    when allow type acls are set

    FLAGS: acl all
    DEPEND:
    CODE: ACL30
    """
    c = env.c1
    c.init_connection()
    res = create_file(c, t.code, attrs={FATTR4_MODE: 0000})
    check(res, msg="Setting mode to 0000 on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'OWNER@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set read owner %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_RUSR)):
        raise FailureException("read user not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'OWNER@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set write owner %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_WUSR)):
        raise FailureException("write user not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'OWNER@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set execute owner %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_XUSR)):
        raise FailureException("execute user not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'GROUP@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set read group %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_RGRP)):
        raise FailureException("read group not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'GROUP@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set write group %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_WGRP)):
        raise FailureException("write group not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'GROUP@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set execute group %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_XGRP)):
        raise FailureException("execute group not set")

    # Reset mode
    ops = c.use_obj(c.homedir + [t.code]) + [c.setattr({FATTR4_MODE: 0000})]
    res = c.compound(ops)
    check(res, msg="Setting 2 mode to 0000 on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set read everyone %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_RUSR)):
        raise FailureException("everyone: read user not set")
    if ( not (mode & MODE4_RGRP)):
        raise FailureException("everyone: read group not set")
    if ( not (mode & MODE4_ROTH)):
        raise FailureException("everyone: read other not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set write everyone %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_WUSR)):
        raise FailureException("everyone: write user not set")
    if ( not (mode & MODE4_WGRP)):
        raise FailureException("everyone: write group not set")
    if ( not (mode & MODE4_WOTH)):
        raise FailureException("everyone: write other not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set execute everyone %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ( not (mode & MODE4_XUSR)):
        raise FailureException("everyone: execute user not set")
    if ( not (mode & MODE4_XGRP)):
        raise FailureException("everyone: execute group not set")
    if ( not (mode & MODE4_XOTH)):
        raise FailureException("everyone: execute other not set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)


def testACLDenyMode(t, env):
    """Test mode bits being taken away
    when deny type acls are set

    FLAGS: acl all
    DEPEND:
    CODE: ACL31
    """
    c = env.c1
    c.init_connection()
    res = create_file(c, t.code, attrs={FATTR4_MODE: 0777})
    check(res, msg="Setting mode to 0777 on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'OWNER@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny read owner %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode & MODE4_RUSR) != 0):
        raise FailureException("read user set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'OWNER@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny write owner %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode & MODE4_WUSR) != 0):
        raise FailureException("write user set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_EXECUTE, 'OWNER@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny execute owner %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode & MODE4_XUSR) != 0):
        raise FailureException("execute user set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'GROUP@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny read group %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode & MODE4_RGRP) != 0):
        raise FailureException("read group set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'GROUP@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny write group %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode & MODE4_WGRP) != 0):
        raise FailureException("write group set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_EXECUTE, 'GROUP@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny execute group %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode & MODE4_XGRP) != 0):
        raise FailureException("execute group set")

    # Reset mode
    ops = c.use_obj(c.homedir + [t.code]) + [c.setattr({FATTR4_MODE: 0777})]
    res = c.compound(ops)
    check(res, msg="Setting 2 mode to 0777 on %s" % t.code)

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny read everyone %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ((mode & MODE4_RUSR) != 0):
        raise FailureException("everyone: read user set")
    if ((mode & MODE4_RGRP) != 0):
        raise FailureException("everyone: read group set")
    if ((mode & MODE4_ROTH) != 0):
        raise FailureException("everyone: read other set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_DATA, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny write everyone %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ((mode & MODE4_WUSR) != 0):
        raise FailureException("everyone: write user set")
    if ((mode & MODE4_WGRP) != 0):
        raise FailureException("everyone: write group set")
    if ((mode & MODE4_WOTH) != 0):
        raise FailureException("everyone: write other set")

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set deny execute everyone %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if ((mode & MODE4_XUSR) != 0):
        raise FailureException("everyone: execute user set")
    if ((mode & MODE4_XGRP) != 0):
        raise FailureException("everyone: execute group set")
    if ((mode & MODE4_XOTH) != 0):
        raise FailureException("everyone: execute other set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)

def testACLConflictingModeAcl(t, env):
    """Test when conflicting mode bits
    and acls are set, mode bits are applied before ACLs.
    7530 - 6.4.1.3

    FLAGS: acl all
    DEPEND:
    CODE: ACL32
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    ops = c.use_obj(fh)

    acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_READ_DATA, 'OWNER@')]
    ops += [c.setattr({FATTR4_ACL: acl, FATTR4_MODE: 0644}, stateid)]
    res = c.compound(ops)
    check(res, msg="Set conflict acl and mode %s" % t.code)
    mode = c.do_getattr(FATTR4_MODE, c.homedir + [t.code])
    if((mode != 0244) != 0):
        raise FailureException("read user set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)

def testACLClearWriteOnInherit(t, env):
    """Inheritance (MAY) clear the
    ACE4_WRITE_ACL and the
    ACE4_WRITE_OWNER bits

    FLAGS: acl all
    DEPEND:
    CODE: ACL33
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                   ACE4_INHERIT_ONLY_ACE, ACE4_WRITE_ACL, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                   ACE4_INHERIT_ONLY_ACE, ACE4_WRITE_OWNER, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit read acls %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="create test dir %s/foo" % t.code)

    inherited_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                             ACE4_INHERIT_ONLY_ACE, ACE4_WRITE_ACL, 'EVERYONE@'),
                     nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@'),
                     nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                             ACE4_INHERIT_ONLY_ACE, ACE4_WRITE_OWNER, 'EVERYONE@'),
                     nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code] + ["foo"])
    if (inherited_acl != cacl):
        raise FailureException("WRITE bits not cleared during inheritance")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)

def testACLModePrecedence1(t, env):
    """When a mode is set, some masks
    that correspond to modes are
    cleared when the "who" field is
    OWNER@ or GROUP@ or EVERYONE@

    FLAGS: acl all
    DEPEND:
    CODE: ACL34
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE,
                   ACE4_LIST_DIRECTORY | ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY |
                   ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'OWNER@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit read acls %s" % t.code)
    res = c.create_obj(c.homedir + [t.code] + ["foo"], type=NF4DIR)
    check(res, msg="create test dir %s/foo" % t.code)
    ops = c.use_obj(c.homedir + [t.code])
    ops += [c.setattr({FATTR4_MODE: 0752})]
    res = c.compound(ops)
    check(res, msg="Set 0752 on %s" % t.code)

    new_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE,
                       ACE4_DIRECTORY_INHERIT_ACE | ACE4_INHERIT_ONLY_ACE,
                       ACE4_LIST_DIRECTORY | ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY |
                       ACE4_EXECUTE, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'OWNER@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, 0, 'OWNER@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_LIST_DIRECTORY | ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY |
                       ACE4_EXECUTE, 'OWNER@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY, 'GROUP@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_LIST_DIRECTORY | ACE4_EXECUTE, 'GROUP@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                       ACE4_LIST_DIRECTORY | ACE4_EXECUTE, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code])
    if (new_acl != cacl):
        raise FailureException("ACL not changed after Mode set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)

def testACLModePrecedence2(t, env):
    """When a mode is set, some masks
    that correspond to modes are
    cleared when the "who" field is
    NOT OWNER@ or GROUP@ or EVERYONE@

    FLAGS: acl all
    DEPEND:
    CODE: ACL35
    """
    #to do:
    #figure out correct owner string
    c = env.c1
    c.init_connection()
    owner = str(env.opts.uid)
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                   ACE4_READ_DATA | ACE4_WRITE_DATA, owner)]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit read acls %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code])
    ops += [c.setattr({FATTR4_MODE: 0552})]
    res = c.compound(ops)
    check(res, msg="Set 0552 on %s" % t.code)

    new_acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, ACE4_WRITE_DATA, owner),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_DATA, owner),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA, 'OWNER@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_READ_DATA | ACE4_EXECUTE, 'OWNER@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA, 'GROUP@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_READ_DATA | ACE4_EXECUTE, 'GROUP@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                       ACE4_READ_DATA | ACE4_EXECUTE, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code])
    if (new_acl != cacl):
        raise FailureException("ACL not changed after Mode set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)

def testACLModePrecedence3(t, env):
    """When a mode is set, some masks
    that correspond to modes are
    cleared when the "who" field is
    NOT OWNER@ or GROUP@ or EVERYONE@
    and ACE4_IDENTIFIER_GROUP is set

    FLAGS: acl all
    DEPEND:
    CODE: ACL36
    """
    c = env.c1
    c.init_connection()
    owner = str(env.opts.gid)
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                   ACE4_READ_DATA | ACE4_WRITE_DATA, owner)]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit read acls %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code])
    ops += [c.setattr({FATTR4_MODE: 0552})]
    res = c.compound(ops)
    check(res, msg="Set 0552 on %s" % t.code)

    new_acl = [nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_WRITE_DATA, owner),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_READ_DATA, owner),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA, 'OWNER@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_READ_DATA | ACE4_EXECUTE, 'OWNER@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA, 'GROUP@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_READ_DATA | ACE4_EXECUTE, 'GROUP@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                       ACE4_READ_DATA | ACE4_EXECUTE, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code])
    if (new_acl != cacl):
        raise FailureException("ACL not adequately changed after Mode set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)

def testACLFinalAces(t, env):
    """When a mode is set, the
    final 6 aces are examined, appended,
    and adjusted according to the
    incoming mode

    FLAGS: acl all
    DEPEND:
    CODE: ACL37
    """
    c = env.c1
    c.init_connection()
    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE,
                   ACE4_READ_DATA, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_EXECUTE, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_LIST_DIRECTORY, 'EVERYONE@'),
           nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_ADD_SUBDIRECTORY, 'EVERYONE@')]
    res = c.create_obj(t.code)
    check(res, msg="create test dir %s" % t.code)
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set inherit read acls %s" % t.code)
    ops = c.use_obj(c.homedir + [t.code])
    ops += [c.setattr({FATTR4_MODE: 0740})]
    res = c.compound(ops)
    check(res, msg="Set 0740 on %s" % t.code)

    new_acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_DIRECTORY_INHERIT_ACE |
                       ACE4_INHERIT_ONLY_ACE , ACE4_READ_DATA, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0, 'EVERYONE@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0, 0, 'OWNER@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA |
                       ACE4_EXECUTE | ACE4_WRITE_ACL | ACE4_WRITE_OWNER |
                       ACE4_WRITE_ATTRIBUTES | ACE4_WRITE_NAMED_ATTRS, 'OWNER@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE, 'GROUP@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_IDENTIFIER_GROUP,
                       ACE4_READ_DATA, 'GROUP@'),
               nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                       ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA |
                       ACE4_EXECUTE | ACE4_WRITE_ACL | ACE4_WRITE_OWNER |
                       ACE4_WRITE_ATTRIBUTES | ACE4_WRITE_NAMED_ATTRS,
                       'EVERYONE@'),
               nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                       ACE4_READ_ACL | ACE4_SYNCHRONIZE | ACE4_READ_ATTRIBUTES |
                       ACE4_READ_NAMED_ATTRS, 'EVERYONE@')]
    cacl = c.do_getattr(FATTR4_ACL, c.homedir + [t.code])
    if (new_acl != cacl):
        raise FailureException("ACL not appended after Mode set")

    acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_DELETE, 'EVERYONE@')]
    res = setacl(c, c.homedir + [t.code], acl)
    check(res, msg="Set delete for cleanup %s" % t.code)
