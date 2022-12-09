package hellojpa;


import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;
import java.util.List;

public class JpaMain {

    public static void main(String[] args) {
       EntityManagerFactory emf = Persistence.createEntityManagerFactory("hello");

        EntityManager em = emf.createEntityManager();
        //code

        EntityTransaction tx = em.getTransaction();
        tx.begin();

        try {
            /*
            회원 등륵
             Member member = new Member();
            member.setId(2L);
            member.setName("SKING");
            em.persist(member);
            */

            // 회원 조회
            //Member findMember = em.find(Member.class, 1L);
            //System.out.println("findMember.id = " + findMember.getId());
            //System.out.println("findMember.name = " + findMember.getName());

            //회원 삭제
            //em.remove(findMember);

            //회원 수정
            //findMember.setName("이히");

            List<Member> result = em.createQuery("select m from Member as m", Member.class)
                    .setFirstResult(5) // 5번째부터
                    .setMaxResults(8) // 8번째까지 페이징
                    .getResultList();

            for (Member member : result) {
                System.out.println("member.name = " + member.getName());
            }

            tx.commit();
        } catch (Exception e) {
            tx.rollback();
        } finally {
            em.close();
        }

        emf.close();
    }
}
