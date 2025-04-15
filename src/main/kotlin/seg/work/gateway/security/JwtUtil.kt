package seg.work.gateway.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import javax.crypto.spec.SecretKeySpec

@Component
class JwtUtil {
    @Value("\${spring.jwt.secret}")
    private lateinit var secret: String
    private val secretKey: SecretKeySpec by lazy { SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().algorithm) }

    fun validateToken(accessToken: String): Boolean {
        try {
            this.parseClaims(accessToken)
            return true
        } catch (e: RuntimeException) {
            return false
        }
    }

    fun parseClaims(accessToken: String): Claims {
        return Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(accessToken)
            .payload
    }
}